<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

use JointIdentityProvider\Oidc\AuthenticatedLogin;
use JointIdentityProvider\Oidc\Configuration\ClientConfiguration;
use JointIdentityProvider\Oidc\Configuration\KeyPair;
use JointIdentityProvider\Oidc\Http\NoAnswer;
use JointIdentityProvider\Oidc\Http\ProviderHttpClient;
use JointIdentityProvider\Oidc\Jose\Base64Url;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;
use JsonException;
use Throwable;

/**
 * Fetches UserInfo with the access token of this login's token response and decrypts it (design §14):
 * a compact JWE with `RSA-OAEP` and `A256CBC-HS512` only, decrypted with one of the client's configured
 * decryption keys. A key whose `kid` equals the JWE header's is tried first, then the others in order.
 */
final readonly class UserInfoReader
{
    public const string KEY_ENCRYPTION = 'RSA-OAEP';
    public const string CONTENT_ENCRYPTION = 'A256CBC-HS512';
    private const int MAX_HEADER_LENGTH = 4096;

    public function __construct(private ProviderHttpClient $http)
    {
    }

    /**
     * Returns the decrypted payload: the envelope as a compact JWS.
     *
     * @throws DeziFailure
     */
    public function read(AuthenticatedLogin $login): string
    {
        $endpoint = $login->metadata->userinfoEndpoint
            ?? throw new DeziFailure(DeziFailureType::UserInfoInvalid, 'discovery names no userinfo_endpoint');

        try {
            $response = $this->http->get($endpoint, [
                'Accept' => 'application/jwt',
                'Authorization' => 'Bearer ' . $login->accessToken,
            ]);
        } catch (NoAnswer $exception) {
            throw new DeziFailure(DeziFailureType::UserInfoUnavailable, 'userinfo: no answer', $exception);
        }

        if ($response->statusCode !== 200) {
            throw new DeziFailure(DeziFailureType::UserInfoRefused, 'userinfo: answer is not HTTP 200');
        }

        return $this->decrypt(trim($response->body), $login->client);
    }

    private function decrypt(string $compact, ClientConfiguration $client): string
    {
        $parts = explode('.', $compact);
        if (count($parts) !== 5 || strlen($parts[0]) > self::MAX_HEADER_LENGTH) {
            throw new DeziFailure(DeziFailureType::UserInfoInvalid, 'userinfo: not a compact JWE');
        }

        $header = self::header($parts[0]);
        if (
            ($header['alg'] ?? null) !== self::KEY_ENCRYPTION
            || ($header['enc'] ?? null) !== self::CONTENT_ENCRYPTION
        ) {
            throw new DeziFailure(DeziFailureType::UserInfoInvalid, 'userinfo: alg or enc is not the specified one');
        }
        if (array_key_exists('zip', $header) || array_key_exists('crit', $header)) {
            throw new DeziFailure(DeziFailureType::UserInfoInvalid, 'userinfo: unsupported header parameter');
        }

        try {
            $jwe = new CompactSerializer()->unserialize($compact);
        } catch (Throwable $exception) {
            throw new DeziFailure(DeziFailureType::UserInfoInvalid, 'userinfo: not a compact JWE', $exception);
        }

        $decrypter = new JWEDecrypter(new AlgorithmManager([new RSAOAEP(), new A256CBCHS512()]));
        $kid = $header['kid'] ?? null;
        foreach (self::keysInOrder($client->decryptionKeys, is_string($kid) ? $kid : null) as $keyPair) {
            $attempt = $jwe;
            try {
                $jwk = JWKFactory::createFromKey($keyPair->privateKeyPem());
                $payload = $decrypter->decryptUsingKey($attempt, $jwk, 0) ? $attempt->getPayload() : null;
            } catch (Throwable) {
                $payload = null;
            }
            if (is_string($payload) && $payload !== '') {
                return $payload;
            }
        }

        throw new DeziFailure(DeziFailureType::UserInfoNotDecrypted, 'userinfo: no configured key decrypts it');
    }

    /**
     * @param list<KeyPair> $keys newest first
     * @return list<KeyPair>
     */
    private static function keysInOrder(array $keys, ?string $kid): array
    {
        $matching = array_filter($keys, static fn (KeyPair $key): bool => $kid !== null && $key->kid === $kid);
        $others = array_filter($keys, static fn (KeyPair $key): bool => $kid === null || $key->kid !== $kid);

        return [...array_values($matching), ...array_values($others)];
    }

    /**
     * @return array<string, mixed>
     */
    private static function header(string $encoded): array
    {
        $json = Base64Url::decode($encoded);
        try {
            $header = $json === null ? null : json_decode($json, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $header = null;
        }
        if (!is_array($header) || array_is_list($header)) {
            throw new DeziFailure(DeziFailureType::UserInfoInvalid, 'userinfo: header is not a JSON object');
        }

        $values = [];
        foreach ($header as $name => $value) {
            $values[(string) $name] = $value;
        }

        return $values;
    }
}
