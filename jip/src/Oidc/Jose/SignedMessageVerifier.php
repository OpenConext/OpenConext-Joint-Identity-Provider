<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Jose;

use InvalidArgumentException;
use JointIdentityProvider\Core\Configuration\ProviderConfiguration;
use JointIdentityProvider\Oidc\Keys\KeyResolver;
use JointIdentityProvider\Oidc\OidcFailure;
use JointIdentityProvider\Oidc\OidcFailureType;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use JsonException;
use Throwable;

/**
 * Verifies a compact JWS signed by the provider with `RS256` only, using a key from the approved key
 * address of its message type (design §14). Keys named in the message (`jwk`, `x5u`, `x5c`) are never
 * used; a supplied `jku` must exactly equal the approved address and is never fetched itself.
 */
final readonly class SignedMessageVerifier
{
    private const int MAX_LENGTH = 65_536;

    public function __construct(private KeyResolver $keys)
    {
    }

    /**
     * @param OidcFailureType $invalid the failure type for a malformed message or a wrong signature
     * @throws OidcFailure
     */
    public function verify(
        string $compact,
        ProviderConfiguration $provider,
        string $messageType,
        OidcFailureType $invalid,
    ): VerifiedMessage {
        if (strlen($compact) > self::MAX_LENGTH) {
            throw new OidcFailure($invalid, $messageType . ': too long');
        }

        try {
            $jws = new CompactSerializer()->unserialize($compact);
        } catch (InvalidArgumentException $exception) {
            throw new OidcFailure($invalid, $messageType . ': not a compact JWS', $exception);
        }

        $signature = $jws->getSignature(0);
        $header = $signature->getProtectedHeader();
        if (($header['alg'] ?? null) !== 'RS256') {
            throw new OidcFailure($invalid, $messageType . ': alg is not RS256');
        }
        if (array_key_exists('crit', $header) || array_key_exists('b64', $header)) {
            throw new OidcFailure($invalid, $messageType . ': unsupported header parameter');
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            throw new OidcFailure($invalid, $messageType . ': no kid');
        }
        if (
            array_key_exists('jku', $header)
            && $header['jku'] !== ($provider->approvedKeyAddresses[$messageType] ?? null)
        ) {
            throw new OidcFailure($invalid, $messageType . ': jku is not the approved key address');
        }

        $claims = self::claims($jws->getPayload());
        if ($claims === null) {
            throw new OidcFailure($invalid, $messageType . ': payload is not a JSON object');
        }

        $key = $this->keys->key($provider, $messageType, $kid);

        try {
            $verified = new JWSVerifier(new AlgorithmManager([new RS256()]))->verifyWithKey($jws, $key, 0);
        } catch (Throwable $exception) {
            throw new OidcFailure($invalid, $messageType . ': signature cannot be verified', $exception);
        }

        if (!$verified) {
            throw new OidcFailure($invalid, $messageType . ': signature is invalid');
        }

        return new VerifiedMessage($header, $claims);
    }

    /**
     * @return array<string, mixed>|null
     */
    private static function claims(?string $payload): ?array
    {
        if ($payload === null || !str_starts_with(ltrim($payload), '{')) {
            return null;
        }

        try {
            $data = json_decode($payload, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (!is_array($data)) {
            return null;
        }

        $claims = [];
        foreach ($data as $name => $value) {
            $claims[(string) $name] = $value;
        }

        return $claims;
    }
}
