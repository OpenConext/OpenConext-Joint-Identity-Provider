<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Configuration;

use JointIdentityProvider\Core\Configuration\Reader\ConfigNode;

/**
 * Validates `provider.issuer`, `provider.authorization` and `provider.clients` (design §14, §17).
 */
final readonly class OidcConfigurationParser
{
    public const array PROVIDER_KEYS = ['issuer', 'authorization', 'clients'];

    public function __construct(private KeyPairReader $keyPairReader)
    {
    }

    public function parse(ConfigNode $provider): ?OidcProviderConfiguration
    {
        $issuer = $provider->get('issuer')->requireHttpsUrl();
        $authorization = $this->parseAuthorization($provider->get('authorization'));
        $clients = $this->parseClients($provider->get('clients'));

        if ($issuer === null || $authorization === null || $clients === null) {
            return null;
        }

        return new OidcProviderConfiguration($issuer, $authorization, $clients);
    }

    private function parseAuthorization(ConfigNode $node): ?AuthorizationParameters
    {
        if (!$node->requireMap()) {
            return null;
        }
        $node->allowOnly('scope', 'prompt', 'max_age');

        $scope = $node->get('scope')->requireString();
        if ($scope !== null && !in_array('openid', explode(' ', $scope), true)) {
            $node->get('scope')->error('must include openid');
            $scope = null;
        }

        $prompt = $node->get('prompt')->optionalString();
        $maxAgeNode = $node->get('max_age');
        $maxAge = $maxAgeNode->optionalNonNegativeInt();

        if (
            $scope === null || ($node->get('prompt')->isPresent() && $prompt === null)
            || ($maxAgeNode->isPresent() && $maxAge === null)
        ) {
            return null;
        }

        return new AuthorizationParameters($scope, $prompt, $maxAge);
    }

    /**
     * @return array<string, ClientConfiguration>|null
     */
    private function parseClients(ConfigNode $node): ?array
    {
        if (!$node->requireMap()) {
            return null;
        }

        $entries = $node->entries();
        if ($entries === []) {
            $node->error('must hold at least one client');

            return null;
        }

        $clients = [];
        $valid = true;
        foreach ($entries as $name => $entry) {
            $client = $this->parseClient($name, $entry);
            if ($client === null) {
                $valid = false;
            } else {
                $clients[$name] = $client;
            }
        }

        return $valid ? $clients : null;
    }

    private function parseClient(string $name, ConfigNode $node): ?ClientConfiguration
    {
        if (!$node->requireMap()) {
            return null;
        }
        $node->allowOnly('client_id', 'redirect_uri', 'authentication', 'signing_key', 'decryption_keys');

        $clientId = $node->get('client_id')->requireString();

        $redirectUriNode = $node->get('redirect_uri');
        $redirectUri = $redirectUriNode->requireHttpsUrl();
        if ($redirectUri !== null) {
            $parts = parse_url($redirectUri);
            if (
                $parts === false || ($parts['path'] ?? '') !== ClientConfiguration::CALLBACK_PATH
                || isset($parts['query']) || isset($parts['fragment'])
            ) {
                $redirectUriNode->error(sprintf(
                    'must have the path %s and no query or fragment',
                    ClientConfiguration::CALLBACK_PATH,
                ));
                $redirectUri = null;
            }
        }

        $authenticationNode = $node->get('authentication');
        $authenticationValue = $authenticationNode->requireString();
        $authentication = $authenticationValue === null ? null : ClientAuthentication::tryFrom($authenticationValue);
        if ($authenticationValue !== null && $authentication === null) {
            $authenticationNode->error('must be private_key_jwt or none');
        }

        $signingKeyNode = $node->get('signing_key');
        $signingKey = null;
        $signingKeyValid = true;
        if ($authentication === ClientAuthentication::PrivateKeyJwt) {
            if (!$signingKeyNode->isPresent()) {
                $signingKeyNode->error('is required with private_key_jwt');
                $signingKeyValid = false;
            } else {
                $signingKey = $this->parseSigningKey($signingKeyNode);
                $signingKeyValid = $signingKey !== null;
            }
        } elseif ($authentication === ClientAuthentication::None && $signingKeyNode->isPresent()) {
            $signingKeyNode->error('must be absent with authentication none');
            $signingKeyValid = false;
        }

        $decryptionKeys = $this->parseDecryptionKeys($node->get('decryption_keys'));

        if (
            $clientId === null || $redirectUri === null || $authentication === null || !$signingKeyValid
            || $decryptionKeys === null
        ) {
            return null;
        }

        return new ClientConfiguration(
            $name,
            $clientId,
            $redirectUri,
            $authentication,
            $signingKey,
            $decryptionKeys,
        );
    }

    private function parseSigningKey(ConfigNode $node): ?SigningKey
    {
        $keyPair = $this->keyPairReader->read($node, ['assertion_lifetime_seconds']);
        $lifetime = $node->get('assertion_lifetime_seconds')->requirePositiveInt();

        return $keyPair === null || $lifetime === null ? null : new SigningKey($keyPair, $lifetime);
    }

    /**
     * @return list<KeyPair>|null
     */
    private function parseDecryptionKeys(ConfigNode $node): ?array
    {
        $items = $node->requireList();
        if ($items === null) {
            return null;
        }

        if ($items === []) {
            $node->error('must hold at least one decryption key');

            return null;
        }

        $keys = [];
        $valid = true;
        foreach ($items as $item) {
            $key = $this->keyPairReader->read($item);
            if ($key === null) {
                $valid = false;
            } else {
                $keys[] = $key;
            }
        }

        return $valid ? $keys : null;
    }
}
