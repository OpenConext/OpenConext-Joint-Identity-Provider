<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

use JointIdentityProvider\Core\Configuration\Reader\ConfigNode;
use JointIdentityProvider\Core\Configuration\Reader\ConfigurationErrors;
use JointIdentityProvider\Core\Profile\ProfileConfiguration;
use JointIdentityProvider\Core\Profile\ProfileRegistry;
use JointIdentityProvider\Core\Profile\ProviderProfile;
use JointIdentityProvider\Oidc\Configuration\OidcConfigurationParser;

/**
 * Turns the parsed configuration tree into a JipConfiguration and runs the startup checks of design §17.
 * Independent checks run even when another value is invalid; dependent checks need usable inputs.
 * The result is null when any problem was reported.
 */
final readonly class ConfigurationParser
{
    private const array ROOT_KEYS = [
        'environment',
        'engineblock',
        'provider',
        'attributes',
        'binding',
        'transactions',
        'services',
    ];

    private const array PROVIDER_KEYS = [
        'profile',
        'approved_key_addresses',
        'expected_issuers',
        'clock_skew_seconds',
        'key_cache_seconds',
        'key_refetch_min_interval_seconds',
        'certificate_expiry_warning_days',
    ];

    public function __construct(
        private ProfileRegistry $profiles,
        private OidcConfigurationParser $oidcParser,
    ) {
    }

    public function parse(
        ConfigNode $root,
        ConfigurationErrors $errors,
        ?string $deploymentEnvironment,
    ): ?JipConfiguration {
        if (!$root->requireMap()) {
            return null;
        }
        $root->allowOnly(...self::ROOT_KEYS);

        $environment = $this->parseEnvironment($root->get('environment'), $errors, $deploymentEnvironment);
        $engineBlockNode = $root->get('engineblock');
        $callTimeout = $engineBlockNode->get('call_timeout_seconds')->requirePositiveInt();
        $engineBlock = $this->parseEngineBlock($engineBlockNode, $callTimeout);

        $providerNode = $root->get('provider');
        $profile = $this->resolveProfile($providerNode);
        $provider = $this->parseProvider($providerNode, $profile, $callTimeout);

        $attributes = $this->parseAttributes($root->get('attributes'), $profile);
        $binding = $this->parseBinding($root->get('binding'), $attributes, $profile);
        $transactions = $this->parseTransactions($root->get('transactions'), $environment);
        $services = $this->parseServices(
            $root->get('services'),
            array_keys($providerNode->get('clients')->entries()),
            $attributes,
        );

        if (
            $environment === null || $engineBlock === null || $provider === null || $attributes === null
            || $binding === null || $transactions === null || $services === null || !$errors->isEmpty()
        ) {
            return null;
        }

        return new JipConfiguration(
            $environment,
            $engineBlock,
            $provider,
            $attributes,
            $binding,
            $transactions,
            $services,
        );
    }

    private function parseEnvironment(
        ConfigNode $node,
        ConfigurationErrors $errors,
        ?string $deploymentEnvironment,
    ): ?Environment {
        $value = $node->requireString();
        $environment = $value === null ? null : Environment::tryFrom($value);
        if ($value !== null && $environment === null) {
            $node->error('must be mock, acceptance or production');
        }

        if ($deploymentEnvironment === null || $deploymentEnvironment === '') {
            $errors->add('CONNECTOR_ENVIRONMENT', 'is not set by the deployment');

            return null;
        }

        if ($environment !== null && $environment->value !== $deploymentEnvironment) {
            $node->error('differs from CONNECTOR_ENVIRONMENT');

            return null;
        }

        return $environment;
    }

    private function parseEngineBlock(ConfigNode $node, ?int $callTimeout): ?EngineBlockConfiguration
    {
        if (!$node->requireMap()) {
            return null;
        }
        $node->allowOnly('api_token', 'call_timeout_seconds', 'return_url_prefix');

        $tokenNode = $node->get('api_token');
        $token = $tokenNode->requireString();
        if ($token !== null && strlen($token) < 32) {
            $tokenNode->error('must be at least 32 characters');
            $token = null;
        }

        $returnUrlNode = $node->get('return_url_prefix');
        $returnUrlPrefix = $returnUrlNode->requireHttpsUrl();
        if ($returnUrlPrefix !== null) {
            $parts = parse_url($returnUrlPrefix);
            if (
                $parts === false || ($parts['path'] ?? '') === ''
                || isset($parts['query']) || isset($parts['fragment'])
            ) {
                $returnUrlNode->error('must include a path and have no query or fragment');
                $returnUrlPrefix = null;
            }
        }

        if ($token === null || $callTimeout === null || $returnUrlPrefix === null) {
            return null;
        }

        return new EngineBlockConfiguration($token, $callTimeout, $returnUrlPrefix);
    }

    private function resolveProfile(ConfigNode $provider): ?ProviderProfile
    {
        $node = $provider->get('profile');
        if (!$provider->isPresent()) {
            return null;
        }

        $name = $node->requireString();
        if ($name === null) {
            return null;
        }

        $profile = $this->profiles->get($name);
        if ($profile === null) {
            $node->error(sprintf('must be one of: %s', implode(', ', $this->profiles->names())));
        }

        return $profile;
    }

    private function parseProvider(
        ConfigNode $node,
        ?ProviderProfile $profile,
        ?int $engineBlockCallTimeoutSeconds,
    ): ?ProviderConfiguration {
        if (!$node->requireMap()) {
            return null;
        }

        $messageTypes = null;
        if ($profile !== null) {
            $node->allowOnly(
                ...self::PROVIDER_KEYS,
                ...OidcConfigurationParser::PROVIDER_KEYS,
                ...$profile->providerKeys(),
            );
            $messageTypes = [ProviderConfiguration::ID_TOKEN, ...$profile->messageTypes()];
        }

        $keyAddresses = $this->parseTrustAnchors($node->get('approved_key_addresses'), $messageTypes, true);
        $issuers = $this->parseTrustAnchors($node->get('expected_issuers'), $messageTypes, false);
        $clockSkew = $node->get('clock_skew_seconds')->requirePositiveInt();
        $keyCache = $node->get('key_cache_seconds')->requirePositiveInt();
        $keyRefetch = $node->get('key_refetch_min_interval_seconds')->requirePositiveInt();
        $expiryWarning = $node->get('certificate_expiry_warning_days')->requirePositiveInt();
        $oidc = $this->oidcParser->parse($node);
        $profileConfiguration = $profile?->parseConfiguration($node, $engineBlockCallTimeoutSeconds);

        if (
            $profile === null || $keyAddresses === null || $issuers === null || $clockSkew === null
            || $keyCache === null || $keyRefetch === null || $expiryWarning === null || $oidc === null
            || !$profileConfiguration instanceof ProfileConfiguration
        ) {
            return null;
        }

        return new ProviderConfiguration(
            $profile->name(),
            $oidc,
            $keyAddresses,
            $issuers,
            $clockSkew,
            $keyCache,
            $keyRefetch,
            $expiryWarning,
            $profileConfiguration,
        );
    }

    /**
     * One value per message type the profile requires; no other message type is accepted.
     *
     * @param list<string>|null $messageTypes null when the profile is unknown
     * @return array<string, string>|null
     */
    private function parseTrustAnchors(ConfigNode $node, ?array $messageTypes, bool $urls): ?array
    {
        if (!$node->requireMap() || $messageTypes === null) {
            return null;
        }

        $valid = true;
        foreach ($node->entries() as $type => $entry) {
            if (!in_array($type, $messageTypes, true)) {
                $entry->error('is not a message type the configured profile uses');
                $valid = false;
            }
        }

        $values = [];
        foreach ($messageTypes as $type) {
            $entry = $node->get($type);
            $value = $urls ? $entry->requireHttpsUrl() : $entry->requireString();
            if ($value === null) {
                $valid = false;
            } else {
                $values[$type] = $value;
            }
        }

        return $valid ? $values : null;
    }

    private function parseAttributes(ConfigNode $node, ?ProviderProfile $profile): ?AttributeMapping
    {
        if (!$node->requireMap()) {
            return null;
        }
        $node->allowOnly('reserved_prefix', 'login_flag', 'claims');

        $prefix = $node->get('reserved_prefix')->requireString();
        $loginFlagNode = $node->get('login_flag');
        $loginFlag = $loginFlagNode->requireString();
        if ($prefix !== null && $loginFlag !== null && !self::liesInside($loginFlag, $prefix)) {
            $loginFlagNode->error('must lie inside attributes.reserved_prefix');
            $loginFlag = null;
        }

        $claims = $this->parseClaims($node->get('claims'), $prefix, $loginFlag, $profile);

        if ($prefix === null || $loginFlag === null || $claims === null) {
            return null;
        }

        return new AttributeMapping($prefix, $loginFlag, $claims);
    }

    /**
     * @return array<string, ClaimMapping>|null
     */
    private function parseClaims(
        ConfigNode $node,
        ?string $prefix,
        ?string $loginFlag,
        ?ProviderProfile $profile,
    ): ?array {
        if (!$node->requireMap()) {
            return null;
        }

        $entries = $node->entries();
        if ($entries === []) {
            $node->error('must map at least one claim');

            return null;
        }

        $claims = [];
        $attributeNames = [];
        $valid = true;
        foreach ($entries as $claim => $entry) {
            if ($profile !== null && !in_array($claim, $profile->claimNames(), true)) {
                $entry->error(sprintf('is not a claim of profile %s', $profile->name()));
                $valid = false;
            }

            $mapping = $this->parseClaim($claim, $entry, $prefix, $loginFlag, $attributeNames);
            if ($mapping === null) {
                $valid = false;
            } else {
                $claims[$claim] = $mapping;
                $attributeNames[] = $mapping->attribute;
            }
        }

        return $valid ? $claims : null;
    }

    /**
     * @param list<string> $attributeNames attribute names mapped so far
     */
    private function parseClaim(
        string $claim,
        ConfigNode $entry,
        ?string $prefix,
        ?string $loginFlag,
        array $attributeNames,
    ): ?ClaimMapping {
        if (!$entry->requireMap()) {
            return null;
        }
        $entry->allowOnly('attribute', 'required', 'default_release');

        $attributeNode = $entry->get('attribute');
        $attribute = $attributeNode->requireString();
        if ($attribute !== null) {
            if ($prefix !== null && !self::liesInside($attribute, $prefix)) {
                $attributeNode->error('must lie inside attributes.reserved_prefix');
                $attribute = null;
            } elseif ($attribute === $loginFlag) {
                $attributeNode->error('must differ from attributes.login_flag');
                $attribute = null;
            } elseif (in_array($attribute, $attributeNames, true)) {
                $attributeNode->error('is already mapped from another claim');
                $attribute = null;
            }
        }

        $required = $entry->get('required')->requireBool();
        $defaultRelease = $entry->get('default_release')->requireBool();

        if ($attribute === null || $required === null || $defaultRelease === null) {
            return null;
        }

        return new ClaimMapping($claim, $attribute, $required, $defaultRelease);
    }

    private function parseBinding(
        ConfigNode $node,
        ?AttributeMapping $attributes,
        ?ProviderProfile $profile,
    ): ?BindingConfiguration {
        if (!$node->requireMap()) {
            return null;
        }
        $node->allowOnly('organisation_attribute', 'claim');

        $attributeNode = $node->get('organisation_attribute');
        $attribute = $attributeNode->requireString();
        if ($attribute !== null && $attributes !== null && str_starts_with($attribute, $attributes->reservedPrefix)) {
            $attributeNode->error('must lie outside attributes.reserved_prefix');
            $attribute = null;
        }

        $claimNode = $node->get('claim');
        $claim = $claimNode->requireString();
        if ($claim !== null && $attributes !== null) {
            $mapping = $attributes->claims[$claim] ?? null;
            if ($mapping === null) {
                $claimNode->error('must name a claim under attributes.claims');
                $claim = null;
            } elseif (!$mapping->required) {
                $claimNode->error('must name a claim marked required under attributes.claims');
                $claim = null;
            }
        }
        if ($claim !== null && $profile !== null && !in_array($claim, $profile->bindingClaims(), true)) {
            $claimNode->error(sprintf('is not a binding claim that profile %s allows', $profile->name()));
            $claim = null;
        }

        return $attribute === null || $claim === null ? null : new BindingConfiguration($attribute, $claim);
    }

    private function parseTransactions(ConfigNode $node, ?Environment $environment): ?TransactionConfiguration
    {
        if (!$node->requireMap()) {
            return null;
        }
        $node->allowOnly('lifetime_seconds', 'store');

        $lifetime = $node->get('lifetime_seconds')->requirePositiveInt();
        $storeNode = $node->get('store');
        $store = $storeNode->requireString();
        if (
            $store !== null
            && (!str_starts_with($store, TransactionConfiguration::SQLITE_PREFIX)
                || trim(substr($store, strlen(TransactionConfiguration::SQLITE_PREFIX))) === '')
        ) {
            $storeNode->error('must be sqlite: followed by a database path (the single-node store)');
            $store = null;
        }

        if ($store !== null && $environment !== null && $environment !== Environment::Mock) {
            $storeNode->error('must be a shared store outside the mock environment');
            $store = null;
        }

        return $lifetime === null || $store === null ? null : new TransactionConfiguration($lifetime, $store);
    }

    /**
     * @param list<string> $clientNames names declared under provider.clients
     * @return array<string, ServicePolicy>|null
     */
    private function parseServices(ConfigNode $node, array $clientNames, ?AttributeMapping $attributes): ?array
    {
        if (!$node->requireMap()) {
            return null;
        }

        $services = [];
        $valid = true;
        foreach ($node->entries() as $serviceId => $entry) {
            $service = $this->parseService($serviceId, $entry, $clientNames, $attributes);
            if ($service === null) {
                $valid = false;
            } else {
                $services[$serviceId] = $service;
            }
        }

        return $valid ? $services : null;
    }

    /**
     * @param list<string> $clientNames
     */
    private function parseService(
        string $serviceId,
        ConfigNode $node,
        array $clientNames,
        ?AttributeMapping $attributes,
    ): ?ServicePolicy {
        if (!$node->requireMap()) {
            return null;
        }
        $node->allowOnly(
            'client',
            'connection_policy_version',
            'allowed_organisations',
            'release',
            'restart_login_url',
        );

        $clientNode = $node->get('client');
        $client = $clientNode->requireString();
        if ($client !== null && !in_array($client, $clientNames, true)) {
            $clientNode->error('must name a client under provider.clients');
            $client = null;
        }

        $policyVersion = $node->get('connection_policy_version')->requireString();
        $organisations = $node->get('allowed_organisations')->requireUniqueStringList();
        $release = $this->parseRelease($node->get('release'), $attributes);
        $restartLoginUrl = $node->get('restart_login_url')->requireHttpsUrl();

        if (
            $client === null || $policyVersion === null || $organisations === null || $release === null
            || $restartLoginUrl === null
        ) {
            return null;
        }

        return new ServicePolicy($serviceId, $client, $policyVersion, $organisations, $release, $restartLoginUrl);
    }

    /**
     * @return list<string>|null
     */
    private function parseRelease(ConfigNode $node, ?AttributeMapping $attributes): ?array
    {
        if (!$node->isPresent()) {
            return $attributes?->defaultReleaseClaims();
        }

        $release = $node->requireUniqueStringList();
        if ($release === null || $attributes === null) {
            return null;
        }

        foreach ($release as $index => $claim) {
            if (!isset($attributes->claims[$claim])) {
                $node->get($index)->error('must name a claim under attributes.claims');
                $release = null;
            }
        }

        return $release;
    }

    private static function liesInside(string $name, string $prefix): bool
    {
        return str_starts_with($name, $prefix) && strlen($name) > strlen($prefix);
    }
}
