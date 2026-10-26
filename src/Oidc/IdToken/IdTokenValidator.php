<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\IdToken;

use DateTimeImmutable;
use JointIdentityProvider\Core\Configuration\ProviderConfiguration;
use JointIdentityProvider\Oidc\Configuration\ClientConfiguration;
use JointIdentityProvider\Oidc\Jose\SignedMessageVerifier;
use JointIdentityProvider\Oidc\OidcFailure;
use JointIdentityProvider\Oidc\OidcFailureType;
use Psr\Clock\ClockInterface;
use SensitiveParameter;

/**
 * Validates the ID token (design §14, OpenID Connect Core §3.1.3.7). Expected values come from the
 * configuration and the transaction, never from the token. `auth_time` must lie after the start of this
 * attempt, so a provider session from before the attempt never counts.
 */
final readonly class IdTokenValidator
{
    public function __construct(
        private SignedMessageVerifier $verifier,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @throws OidcFailure
     */
    public function validate(
        #[SensitiveParameter] string $idToken,
        ProviderConfiguration $provider,
        ClientConfiguration $client,
        #[SensitiveParameter] string $expectedNonce,
        DateTimeImmutable $attemptStartedAt,
    ): IdTokenClaims {
        $claims = $this->verifier->verify(
            $idToken,
            $provider,
            ProviderConfiguration::ID_TOKEN,
            OidcFailureType::IdTokenInvalid,
        )->claims;

        if (($claims['iss'] ?? null) !== $provider->expectedIssuers[ProviderConfiguration::ID_TOKEN]) {
            throw self::invalid('iss differs from provider.expected_issuers.id_token');
        }

        $audience = $claims['aud'] ?? null;
        if ($audience !== $client->clientId && $audience !== [$client->clientId]) {
            throw self::invalid('aud is not exactly the client ID');
        }
        if (array_key_exists('azp', $claims) && $claims['azp'] !== $client->clientId) {
            throw self::invalid('azp is not the client ID');
        }

        $subject = $claims['sub'] ?? null;
        if (!is_string($subject) || $subject === '') {
            throw self::invalid('sub is missing');
        }

        $nonce = $claims['nonce'] ?? null;
        if (!is_string($nonce) || !hash_equals($expectedNonce, $nonce)) {
            throw self::invalid('nonce differs from the stored value');
        }

        $issuedAt = self::numericDate($claims, 'iat');
        $expiresAt = self::numericDate($claims, 'exp');
        $authTime = self::numericDate($claims, 'auth_time');
        $now = (float) $this->clock->now()->format('U.u');
        $skew = $provider->clockSkewSeconds;

        if ($expiresAt <= $now - $skew) {
            throw self::invalid('exp has passed');
        }
        if ($issuedAt > $now + $skew) {
            throw self::invalid('iat lies in the future');
        }
        if (array_key_exists('nbf', $claims) && self::numericDate($claims, 'nbf') > $now + $skew) {
            throw self::invalid('nbf lies in the future');
        }
        // auth_time has whole seconds; the attempt start is compared at the same precision.
        if ($authTime < $attemptStartedAt->getTimestamp() - $skew) {
            throw self::invalid('auth_time lies before the attempt start');
        }
        if ($authTime > $now + $skew) {
            throw self::invalid('auth_time lies in the future');
        }

        return new IdTokenClaims($subject, (int) floor($authTime), $claims);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function numericDate(array $claims, string $name): float
    {
        $value = $claims[$name] ?? null;
        if ((!is_int($value) && !is_float($value)) || !is_finite((float) $value) || $value < 0) {
            throw self::invalid($name . ' is missing or not a number');
        }

        return (float) $value;
    }

    private static function invalid(string $detail): OidcFailure
    {
        return new OidcFailure(OidcFailureType::IdTokenInvalid, 'id_token: ' . $detail);
    }
}
