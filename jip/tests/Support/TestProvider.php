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
    public const string ENVELOPE_JWKS = self::ISSUER . '/envelope/jwks.json';
    public const string STATEMENT_JWKS = self::ISSUER . '/dezi/jwks.json';
    public const string STATUS_PREFIX = self::ISSUER . '/status/v1/verklaring/';
    public const string CLIENT_ID = 'jip-mock-ggd';
    public const string KID = 'test-id-token-key';
    public const string ENVELOPE_KID = 'test-envelope-key';
    public const string STATEMENT_KID = 'test-statement-key';
    public const string ENVELOPE_ISSUER = 'auth.mock-dezi.dev.openconext.local';
    public const string STATEMENT_ISSUER = 'abonnee.mock-dezi.dev.openconext.local';
    public const string ENVELOPE_AUDIENCE = 'jip-mock-ggd-envelope';
    public const string LOA_AUTHN = 'http://eidas.europa.eu/LoA/high';
    public const string LOA_DEZI = 'http://eidas.europe.eu/LoA/high';
    public const string VERKLARING_ID = 'd3e2a1c0-0001-4000-8000-000000000001';
    public const string SUBJECT = 'pairwise-subject';

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

    /** The certificate UserInfo is encrypted to; without one, UserInfo answers 404. */
    public ?string $userInfoRecipient = null;

    /** @var array<string, mixed> JWE header values to add or replace */
    public array $userInfoHeader = [];

    /** @var array<string, mixed> envelope claims to add or replace; the value ABSENT removes one */
    public array $envelopeClaims = [];

    /** @var array<string, mixed> statement claims to add or replace; the value ABSENT removes one */
    public array $statementClaims = [];

    /** @var array<string, mixed> header values to add or replace */
    public array $envelopeHeader = [];

    /** @var array<string, mixed> header values to add or replace */
    public array $statementHeader = [];

    public string $envelopeSigningKey = self::ENVELOPE_KID;
    public string $statementSigningKey = self::STATEMENT_KID;

    /** The status every status check answers, for the ID it was asked about. */
    public string $status = 'actief';

    /** The time the messages are issued at; null for the current time. */
    public ?int $now = null;

    public const string ABSENT = "\0absent";

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
            self::ENVELOPE_JWKS => self::json(['keys' => [self::publicJwk(self::ENVELOPE_KID, self::ENVELOPE_KID)]]),
            self::STATEMENT_JWKS => self::json(['keys' => [self::publicJwk(self::STATEMENT_KID, self::STATEMENT_KID)]]),
            self::TOKEN => self::json([
                'access_token' => 'test-access-token',
                'token_type' => 'Bearer',
                'expires_in' => 300,
                'id_token' => $this->idToken(),
            ]),
            self::USERINFO => $this->userInfoRecipient === null
                ? new MockResponse('not found', ['http_code' => 404])
                : new MockResponse($this->userInfo(), ['response_headers' => ['Content-Type' => 'application/jwt']]),
            default => str_starts_with($url, self::STATUS_PREFIX)
                ? self::json(['verklaringId' => rawurldecode(substr($url, strlen(self::STATUS_PREFIX))), 'status' => $this->status])
                : new MockResponse('not found', ['http_code' => 404]),
        };
    }

    public function statusUrl(string $verklaringId = self::VERKLARING_ID): string
    {
        return self::STATUS_PREFIX . $verklaringId;
    }

    /**
     * The UserInfo answer: a JWE (RSA-OAEP, A256CBC-HS512) to $userInfoRecipient around the signed envelope,
     * which carries the sealed statement. Built with plain OpenSSL, independently of JIP's JOSE code.
     */
    public function userInfo(): string
    {
        if ($this->userInfoRecipient === null) {
            throw new RuntimeException('No UserInfo recipient is set.');
        }

        return self::encrypt($this->envelope(), $this->userInfoRecipient, $this->userInfoHeader);
    }

    public function envelope(): string
    {
        $now = $this->now ?? time();
        $claims = self::apply([
            'iss' => self::ENVELOPE_ISSUER,
            'aud' => self::ENVELOPE_AUDIENCE,
            'iat' => $now,
            'exp' => $now + 300,
            'loa_authn' => self::LOA_AUTHN,
            'verklaring_id' => self::VERKLARING_ID,
            'verklaring' => $this->statement(),
        ], $this->envelopeClaims);

        return self::sign(
            self::apply(['alg' => 'RS256', 'kid' => self::ENVELOPE_KID], $this->envelopeHeader),
            $claims,
            $this->envelopeSigningKey,
        );
    }

    public function statement(): string
    {
        $now = $this->now ?? time();
        $claims = self::apply([
            'jti' => 'b5c1f0a2-0000-4000-8000-000000000001',
            'iss' => self::STATEMENT_ISSUER,
            'nbf' => $now - 60,
            'exp' => $now + 86400,
            'json_schema' => self::ISSUER . '/schema/verklaring-mock.json',
            'dezi_nummer' => '900000001',
            'voorletters' => 'A.',
            'voorvoegsel' => null,
            'achternaam' => 'Mockarts',
            'abonnee_nummer' => '90000001',
            'abonnee_naam' => 'Mock GGD Noord',
            'rol_code' => '01.000',
            'rol_naam' => 'Arts',
            'rol_code_bron' => 'mock-bron',
            'loa_dezi' => self::LOA_DEZI,
            'verklaring_id' => self::VERKLARING_ID,
            'status_uri' => self::ISSUER . '/statement-link/status/' . self::VERKLARING_ID,
            'revocatie_controle_uri' => self::ISSUER . '/statement-link/revocatie/' . self::VERKLARING_ID,
        ], $this->statementClaims);

        return self::sign(
            self::apply(
                ['alg' => 'RS256', 'kid' => self::STATEMENT_KID, 'jku' => self::STATEMENT_JWKS],
                $this->statementHeader,
            ),
            $claims,
            $this->statementSigningKey,
        );
    }

    /**
     * @param array<string, mixed> $header values to add or replace in {alg, enc, kid}
     */
    public static function encrypt(string $payload, string $recipientPem, array $header = []): string
    {
        $header = self::apply(['alg' => 'RSA-OAEP', 'enc' => 'A256CBC-HS512'], $header);
        $protected = self::b64(self::encode($header));
        $cek = random_bytes(64);
        $iv = random_bytes(16);
        $ciphertext = openssl_encrypt($payload, 'aes-256-cbc', substr($cek, 32), OPENSSL_RAW_DATA, $iv);
        $digest = ($header['alg'] ?? null) === 'RSA-OAEP-256' ? 'sha256' : 'sha1';
        if (
            $ciphertext === false
            || !openssl_public_encrypt($cek, $encryptedKey, $recipientPem, OPENSSL_PKCS1_OAEP_PADDING, $digest)
            || !is_string($encryptedKey)
        ) {
            throw new RuntimeException('Cannot encrypt a test message.');
        }
        $mac = hash_hmac('sha512', $protected . $iv . $ciphertext . pack('J', strlen($protected) * 8), substr($cek, 0, 32), true);

        return implode('.', [$protected, self::b64($encryptedKey), self::b64($iv), self::b64($ciphertext), self::b64(substr($mac, 0, 32))]);
    }

    /**
     * @param array<string, mixed> $values
     * @param array<string, mixed> $changes
     * @return array<string, mixed>
     */
    private static function apply(array $values, array $changes): array
    {
        foreach ($changes as $name => $value) {
            if ($value === self::ABSENT) {
                unset($values[$name]);
            } else {
                $values[$name] = $value;
            }
        }

        return $values;
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
        $now = $this->now ?? time();
        $claims = [
            'iss' => self::ISSUER,
            'sub' => self::SUBJECT,
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
