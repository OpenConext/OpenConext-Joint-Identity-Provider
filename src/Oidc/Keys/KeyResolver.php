<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Keys;

use JointIdentityProvider\Oidc\Cache\ProviderCache;
use JointIdentityProvider\Oidc\Configuration\TrustSettings;
use JointIdentityProvider\Oidc\Http\NoAnswer;
use JointIdentityProvider\Oidc\Http\ProviderHttpClient;
use JointIdentityProvider\Oidc\OidcFailure;
use JointIdentityProvider\Oidc\OidcFailureType;
use Jose\Component\Core\JWK;
use LogicException;
use Psr\Clock\ClockInterface;

/**
 * Finds a provider signing key for one message type, only at that type's approved key address
 * (design §14). Key sets are kept per address for `provider.key_cache_seconds`; a `kid` is looked up only
 * in the set of the current message type. An unknown `kid` triggers at most one new fetch from the same
 * address per `provider.key_refetch_min_interval_seconds`. A failed fetch keeps the kept keys until their
 * time ends. During the refetch interval, a failed fetch keeps its failure classification.
 */
final readonly class KeyResolver
{
    public function __construct(
        private ProviderHttpClient $http,
        private ProviderCache $cache,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @throws OidcFailure
     */
    public function key(TrustSettings $trust, string $messageType, string $kid): JWK
    {
        $address = $trust->approvedKeyAddresses[$messageType]
            ?? throw new LogicException('The message type has no approved key address.');

        $result = $this->cache->update(
            'jwks ' . $address,
            function (?array $entry) use ($trust, $messageType, $address, $kid): array {
                $now = (float) $this->clock->now()->format('U.u');
                $fetchedAt = self::number($entry['fetched_at'] ?? null);
                $lastAttemptAt = self::number($entry['last_attempt_at'] ?? null) ?? $fetchedAt;
                $keys = self::keptKeys($entry['keys'] ?? null);
                $fresh = $fetchedAt !== null && $keys !== null
                    && $now >= $fetchedAt && $now < $fetchedAt + $trust->keyCacheSeconds;

                if ($fresh && isset($keys[$kid])) {
                    return [null, new JWK($keys[$kid])];
                }
                if (
                    $lastAttemptAt !== null && $now >= $lastAttemptAt
                    && $now < $lastAttemptAt + $trust->keyRefetchMinIntervalSeconds
                    && ($fresh || isset($entry['last_fetch_failure']))
                ) {
                    $failure = match ($entry['last_fetch_failure'] ?? null) {
                        OidcFailureType::KeyFetchUnavailable->value => new OidcFailure(
                            OidcFailureType::KeyFetchUnavailable,
                            $messageType . ' key set: previous fetch got no answer',
                        ),
                        OidcFailureType::KeySetInvalid->value => new OidcFailure(
                            OidcFailureType::KeySetInvalid,
                            $messageType . ' key set: previous fetch was refused',
                        ),
                        default => self::unknownKey($messageType),
                    };

                    return [null, $failure];
                }

                $kept = $fresh ? ['fetched_at' => $fetchedAt, 'keys' => $keys] : [];
                $fetched = $this->fetch($address, $messageType);
                if ($fetched instanceof OidcFailure) {
                    return [[
                        'last_attempt_at' => $now,
                        'last_fetch_failure' => $fetched->type->value,
                    ] + $kept, $fetched];
                }

                $next = ['fetched_at' => $now, 'last_attempt_at' => $now, 'keys' => $fetched];

                return [$next, isset($fetched[$kid]) ? new JWK($fetched[$kid]) : self::unknownKey($messageType)];
            },
        );

        if ($result instanceof OidcFailure) {
            throw $result;
        }

        return $result;
    }

    /**
     * @return array<string, array<string, string>>|OidcFailure
     */
    private function fetch(string $address, string $messageType): array|OidcFailure
    {
        try {
            $response = $this->http->get($address);
        } catch (NoAnswer $exception) {
            return new OidcFailure(
                OidcFailureType::KeyFetchUnavailable,
                $messageType . ' key set: no answer',
                $exception,
            );
        }

        if ($response->statusCode !== 200) {
            return new OidcFailure(OidcFailureType::KeySetInvalid, $messageType . ' key set: answer is not HTTP 200');
        }

        $keySet = $response->jsonObject();
        $entries = $keySet['keys'] ?? null;
        if (!is_array($entries) || !array_is_list($entries)) {
            return new OidcFailure(OidcFailureType::KeyFetchUnavailable, $messageType . ' key set: invalid body');
        }

        return self::signingKeys($entries);
    }

    /**
     * RSA signing keys with a `kid`. A `kid` that occurs more than once is ambiguous and dropped.
     *
     * @param list<mixed> $entries
     * @return array<string, array<string, string>>
     */
    private static function signingKeys(array $entries): array
    {
        $keys = [];
        $seen = [];
        foreach ($entries as $entry) {
            $kid = is_array($entry) ? ($entry['kid'] ?? null) : null;
            if (!is_string($kid) || $kid === '') {
                continue;
            }
            $seen[$kid] = ($seen[$kid] ?? 0) + 1;

            $key = self::rsaSigningKey($entry);
            if ($key !== null) {
                $keys[$kid] = $key;
            }
        }

        return array_filter($keys, static fn (string $kid): bool => $seen[$kid] === 1, ARRAY_FILTER_USE_KEY);
    }

    /**
     * @param array<mixed> $entry
     * @return array<string, string>|null
     */
    private static function rsaSigningKey(array $entry): ?array
    {
        $kid = $entry['kid'] ?? null;
        $n = $entry['n'] ?? null;
        $e = $entry['e'] ?? null;
        $use = $entry['use'] ?? 'sig';
        $alg = $entry['alg'] ?? 'RS256';
        if (
            ($entry['kty'] ?? null) !== 'RSA' || !is_string($kid) || !is_string($n) || !is_string($e)
            || $use !== 'sig' || $alg !== 'RS256'
            || preg_match('/^[A-Za-z0-9_-]+\z/', $n . $e) !== 1
        ) {
            return null;
        }

        return ['kty' => 'RSA', 'kid' => $kid, 'n' => $n, 'e' => $e];
    }

    /**
     * @return array<string, array<string, string>>|null
     */
    private static function keptKeys(mixed $value): ?array
    {
        if (!is_array($value)) {
            return null;
        }

        $keys = [];
        foreach ($value as $kid => $key) {
            $kept = is_array($key) ? self::rsaSigningKey($key) : null;
            if ($kept === null || $kept['kid'] !== (string) $kid) {
                return null;
            }
            $keys[(string) $kid] = $kept;
        }

        return $keys;
    }

    private static function number(mixed $value): ?float
    {
        return is_int($value) || is_float($value) ? (float) $value : null;
    }

    private static function unknownKey(string $messageType): OidcFailure
    {
        return new OidcFailure(OidcFailureType::UnknownKey, $messageType . ': kid not in the approved key set');
    }
}
