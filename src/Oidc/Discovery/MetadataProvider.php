<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Discovery;

use JointIdentityProvider\Configuration\Reader\ConfigNode;
use JointIdentityProvider\Oidc\Cache\ProviderCache;
use JointIdentityProvider\Oidc\Configuration\OidcProviderConfiguration;
use JointIdentityProvider\Oidc\Configuration\TrustSettings;
use JointIdentityProvider\Oidc\Http\NoAnswer;
use JointIdentityProvider\Oidc\Http\ProviderHttpClient;
use JointIdentityProvider\Oidc\OidcFailure;
use JointIdentityProvider\Oidc\OidcFailureType;
use Psr\Clock\ClockInterface;

/**
 * Loads the provider's discovery metadata from `<issuer>/.well-known/openid-configuration`, the only
 * address the configured issuer allows (design §14). Validated metadata is kept for
 * `provider.key_cache_seconds`; kept metadata is validated again against the current configuration
 * before every use.
 */
final readonly class MetadataProvider
{
    public const string WELL_KNOWN_PATH = '/.well-known/openid-configuration';

    public function __construct(
        private ProviderHttpClient $http,
        private ProviderCache $cache,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @throws OidcFailure
     */
    public function load(OidcProviderConfiguration $provider, TrustSettings $trust): ProviderMetadata
    {
        $issuer = $provider->issuer;

        $result = $this->cache->update(
            'discovery ' . $issuer,
            function (?array $entry) use ($provider, $trust, $issuer): array {
                $now = (float) $this->clock->now()->format('U.u');

                $fetchedAt = $entry['fetched_at'] ?? null;
                $document = $entry['document'] ?? null;
                if (
                    (is_int($fetchedAt) || is_float($fetchedAt)) && is_array($document)
                    && $now >= $fetchedAt && $now < $fetchedAt + $trust->keyCacheSeconds
                ) {
                    $kept = self::validate(self::stringKeys($document), $provider, $trust);
                    if ($kept instanceof ProviderMetadata) {
                        return [null, $kept];
                    }
                }

                $lastAttemptAt = $entry['last_attempt_at'] ?? null;
                $failureType = match ($entry['last_failure'] ?? null) {
                    OidcFailureType::DiscoveryUnavailable->value => OidcFailureType::DiscoveryUnavailable,
                    OidcFailureType::DiscoveryInvalid->value => OidcFailureType::DiscoveryInvalid,
                    default => null,
                };
                if (
                    $failureType !== null && (is_int($lastAttemptAt) || is_float($lastAttemptAt))
                    && $now >= $lastAttemptAt
                    && $now < $lastAttemptAt + $trust->keyRefetchMinIntervalSeconds
                ) {
                    return [null, new OidcFailure($failureType, 'previous discovery fetch failed')];
                }

                $fetched = $this->fetch($issuer);
                $metadata = $fetched instanceof OidcFailure ? $fetched : self::validate($fetched, $provider, $trust);
                if ($metadata instanceof OidcFailure) {
                    return [[
                        'last_attempt_at' => $now,
                        'last_failure' => $metadata->type->value,
                    ], $metadata];
                }

                return [['fetched_at' => $now, 'document' => $fetched], $metadata];
            },
        );

        if ($result instanceof OidcFailure) {
            throw $result;
        }

        return $result;
    }

    /**
     * @return array<string, mixed>|OidcFailure
     */
    private function fetch(string $issuer): array|OidcFailure
    {
        try {
            $response = $this->http->get(rtrim($issuer, '/') . self::WELL_KNOWN_PATH);
        } catch (NoAnswer $exception) {
            return new OidcFailure(OidcFailureType::DiscoveryUnavailable, 'no answer', $exception);
        }

        if ($response->statusCode !== 200) {
            return new OidcFailure(OidcFailureType::DiscoveryInvalid, 'answer is not HTTP 200');
        }

        return $response->jsonObject()
            ?? new OidcFailure(OidcFailureType::DiscoveryUnavailable, 'invalid body');
    }

    /**
     * @param array<string, mixed> $document
     */
    private static function validate(
        array $document,
        OidcProviderConfiguration $provider,
        TrustSettings $trust,
    ): ProviderMetadata|OidcFailure {
        if (($document['issuer'] ?? null) !== $provider->issuer) {
            return new OidcFailure(OidcFailureType::DiscoveryInvalid, 'issuer differs from provider.issuer');
        }

        $jwksUri = $trust->approvedKeyAddresses[TrustSettings::ID_TOKEN];
        if (($document['jwks_uri'] ?? null) !== $jwksUri) {
            return new OidcFailure(
                OidcFailureType::DiscoveryInvalid,
                'jwks_uri differs from provider.approved_key_addresses.id_token',
            );
        }

        $authorizationEndpoint = self::endpoint($document['authorization_endpoint'] ?? null);
        $tokenEndpoint = self::endpoint($document['token_endpoint'] ?? null);
        $userinfo = $document['userinfo_endpoint'] ?? null;
        $userinfoEndpoint = $userinfo === null ? null : self::endpoint($userinfo);
        if (
            $authorizationEndpoint === null
            || $tokenEndpoint === null
            || ($userinfo !== null && $userinfoEndpoint === null)
        ) {
            return new OidcFailure(OidcFailureType::DiscoveryInvalid, 'an endpoint is not an absolute https URL');
        }

        // Without the field, OIDC Discovery's default is client_secret_basic, which JIP never uses.
        $methods = $document['token_endpoint_auth_methods_supported'] ?? [];
        if (!is_array($methods) || !array_is_list($methods)) {
            return new OidcFailure(
                OidcFailureType::DiscoveryInvalid,
                'token_endpoint_auth_methods_supported is not a list',
            );
        }

        return new ProviderMetadata(
            $provider->issuer,
            $authorizationEndpoint,
            $tokenEndpoint,
            $jwksUri,
            $userinfoEndpoint,
            array_values(array_filter($methods, is_string(...))),
        );
    }

    private static function endpoint(mixed $value): ?string
    {
        return is_string($value) && ConfigNode::isAbsoluteHttpsUrl($value) && !str_contains($value, '#')
            ? $value
            : null;
    }

    /**
     * @param array<mixed> $data
     * @return array<string, mixed>
     */
    private static function stringKeys(array $data): array
    {
        $result = [];
        foreach ($data as $key => $value) {
            $result[(string) $key] = $value;
        }

        return $result;
    }
}
