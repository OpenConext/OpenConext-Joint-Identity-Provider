<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Support;

use Closure;
use OpenSSLAsymmetricKey;
use RuntimeException;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * A fake provider for JIP's outgoing requests in tests (the MockHttpClient factory). It signs with plain
 * OpenSSL, independently of JIP's JOSE code. Addresses follow config/jip/mock.yaml.
 */
final class TestProvider
{
    public const string ISSUER = 'https://mock-dezi.dev.openconext.local';
    public const string DISCOVERY = self::ISSUER . '/.well-known/openid-configuration';
    public const string AUTHORIZE = self::ISSUER . '/authorize';
    public const string TOKEN = self::ISSUER . '/token';
    public const string USERINFO = self::ISSUER . '/userinfo';
    public const string ID_TOKEN_JWKS = self::ISSUER . '/openid/connect/jwks.json';
    public const string STATEMENT_JWKS = self::ISSUER . '/dezi/jwks.json';
    public const string CLIENT_ID = 'jip-mock-ggd';
    public const string KID = 'test-id-token-key';

    /** @var list<array{method: string, url: string, options: array<string, mixed>}> */
    public array $requests = [];

    /** @var array<string, mixed> */
    public array $discovery;

    /** @var array<string, Closure(string, array<string, mixed>): MockResponse> answers by URL, replacing the default */
    public array $answers = [];

    /** The nonce for the next ID token; tests copy it from the authorisation request. */
    public string $nonce = '';

    /** @var array<string, mixed> ID-token claims to add or, with null, remove */
    public array $idTokenClaims = [];

    /** @var array<string, array{OpenSSLAsymmetricKey, string, string}> */
    private static array $keys = [];

    public function __construct()
    {
        $this->discovery = [
            'issuer' => self::ISSUER,
            'authorization_endpoint' => self::AUTHORIZE,
            'token_endpoint' => self::TOKEN,
            'userinfo_endpoint' => self::USERINFO,
            'jwks_uri' => self::ID_TOKEN_JWKS,
            'response_types_supported' => ['code'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['none', 'private_key_jwt'],
        ];
    }

    /**
     * @param array<string, mixed> $options
     */
    public function __invoke(string $method, string $url, array $options): ResponseInterface
    {
        $this->requests[] = ['method' => $method, 'url' => $url, 'options' => $options];

        if (isset($this->answers[$url])) {
            return ($this->answers[$url])($method, $options);
        }

        return match ($url) {
            self::DISCOVERY => self::json($this->discovery),
            self::ID_TOKEN_JWKS => self::json(['keys' => [self::publicJwk(self::KID)]]),
            self::TOKEN => self::json([
                'access_token' => 'test-access-token',
                'token_type' => 'Bearer',
                'expires_in' => 300,
                'id_token' => $this->idToken(),
            ]),
            default => new MockResponse('not found', ['http_code' => 404]),
        };
    }

    /**
     * @param list<string> $urls
     */
    public function countRequests(array $urls): int
    {
        return count(array_filter($this->requests, static fn (array $r): bool => in_array($r['url'], $urls, true)));
    }

    /**
     * @return array<string, string>
     */
    public function lastTokenRequestForm(): array
    {
        foreach (array_reverse($this->requests) as $request) {
            if ($request['url'] === self::TOKEN) {
                $body = $request['options']['body'] ?? '';
                parse_str(is_string($body) ? $body : '', $form);

                $fields = [];
                foreach ($form as $name => $value) {
                    $fields[(string) $name] = is_string($value) ? $value : '';
                }

                return $fields;
            }
        }

        throw new RuntimeException('No token request was made.');
    }

    public function idToken(): string
    {
        $now = time();
        $claims = [
            'iss' => self::ISSUER,
            'sub' => 'pairwise-subject',
            'aud' => self::CLIENT_ID,
            'iat' => $now,
            'exp' => $now + 300,
            'auth_time' => $now,
            'nonce' => $this->nonce,
        ];
        foreach ($this->idTokenClaims as $name => $value) {
            if ($value === null) {
                unset($claims[$name]);
            } else {
                $claims[$name] = $value;
            }
        }

        return self::sign(['alg' => 'RS256', 'kid' => self::KID], $claims);
    }

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    public static function sign(array $header, array $claims, string $keyName = self::KID): string
    {
        $input = self::b64(self::encode($header)) . '.' . self::b64(self::encode($claims));
        if (!openssl_sign($input, $signature, self::key($keyName)[0], OPENSSL_ALGO_SHA256) || !is_string($signature)) {
            throw new RuntimeException('Cannot sign a test message.');
        }

        return $input . '.' . self::b64($signature);
    }

    /**
     * @return array<string, string>
     */
    public static function publicJwk(string $kid, string $keyName = self::KID): array
    {
        [, $n, $e] = self::key($keyName);

        return ['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => $n, 'e' => $e];
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function json(array $data, int $status = 200): MockResponse
    {
        return new MockResponse(self::encode($data), [
            'http_code' => $status,
            'response_headers' => ['Content-Type' => 'application/json'],
        ]);
    }

    public static function b64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * @return array{OpenSSLAsymmetricKey, string, string} the private key and its base64url n and e
     */
    private static function key(string $name): array
    {
        if (!isset(self::$keys[$name])) {
            $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
            $details = $key instanceof OpenSSLAsymmetricKey ? openssl_pkey_get_details($key) : false;
            $rsa = is_array($details) ? ($details['rsa'] ?? null) : null;
            if (!$key instanceof OpenSSLAsymmetricKey || !is_array($rsa) || !is_string($rsa['n'] ?? null) || !is_string($rsa['e'] ?? null)) {
                throw new RuntimeException('Cannot generate a test key.');
            }
            self::$keys[$name] = [$key, self::b64($rsa['n']), self::b64($rsa['e'])];
        }

        return self::$keys[$name];
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function encode(array $data): string
    {
        return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
