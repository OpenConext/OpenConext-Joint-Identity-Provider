<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Token;

use JointIdentityProvider\Oidc\Configuration\ClientConfiguration;
use JointIdentityProvider\Oidc\Jose\Base64Url;
use LogicException;
use OpenSSLCertificate;
use Psr\Clock\ClockInterface;
use RuntimeException;

/**
 * The client assertion for `private_key_jwt` (OpenID Connect Core §9, design §14): a compact JWS signed
 * `RS256` with the client's signing key. A new assertion, with a new `jti`, for every token request;
 * it is never stored or logged.
 */
final readonly class ClientAssertionFactory
{
    public const string ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    public function __construct(private ClockInterface $clock)
    {
    }

    public function create(ClientConfiguration $client, string $tokenEndpoint): string
    {
        $signingKey = $client->signingKey
            ?? throw new LogicException('A private_key_jwt client has a signing key.');
        $keyPair = $signingKey->keyPair;

        $certificate = openssl_x509_read($keyPair->certificatePem);
        $thumbprint = $certificate instanceof OpenSSLCertificate
            ? openssl_x509_fingerprint($certificate, 'sha256', true)
            : false;
        if ($thumbprint === false) {
            throw new RuntimeException('Cannot compute the signing certificate thumbprint.');
        }

        $header = ['alg' => 'RS256'];
        if ($keyPair->kid !== null) {
            $header['kid'] = $keyPair->kid;
        }
        $header['x5t#S256'] = Base64Url::encode($thumbprint);

        $issuedAt = $this->clock->now()->getTimestamp();
        $claims = [
            'iss' => $client->clientId,
            'sub' => $client->clientId,
            'aud' => $tokenEndpoint,
            'iat' => $issuedAt,
            'exp' => $issuedAt + $signingKey->assertionLifetimeSeconds,
            'jti' => Base64Url::randomToken(),
        ];

        $signingInput = Base64Url::encode(self::json($header)) . '.' . Base64Url::encode(self::json($claims));
        if (
            !openssl_sign($signingInput, $signature, $keyPair->privateKeyPem(), OPENSSL_ALGO_SHA256)
            || !is_string($signature)
        ) {
            throw new RuntimeException('Cannot sign the client assertion.');
        }

        return $signingInput . '.' . Base64Url::encode($signature);
    }

    /**
     * @param array<string, string|int> $data
     */
    private static function json(array $data): string
    {
        return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
