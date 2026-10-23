<?php

declare(strict_types=1);

namespace MockDezi\Tests\Support;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use MockDezi\Message\Jose;
use PHPUnit\Framework\Assert;
use RuntimeException;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
use WeakMap;

/**
 * Plays JIP against the mock DEZI provider in tests: builds the requests and checks the answers independently
 * of the mock's own code (the JWE is decrypted with plain OpenSSL).
 */
final class JipSimulator
{
    public const string ISSUER = 'https://mock-dezi.dev.openconext.local';
    public const string TOKEN_ENDPOINT = self::ISSUER . '/token';

    /** @var WeakMap<JWKSet, string> */
    private static WeakMap $keyAddresses;

    public string $verifier;
    public string $state;
    public string $nonce;
    public int $attemptStart;

    public function __construct(
        private readonly KernelBrowser $browser,
        private readonly MockDeziFixture $fixture,
        public string $clientId = MockDeziFixture::CLIENT_ID,
    ) {
        $this->verifier = Jose::randomToken();
        $this->state = Jose::randomToken();
        $this->nonce = Jose::randomToken();
        $this->attemptStart = time();
    }

    /**
     * @param array<string, string|null> $override null removes a parameter
     */
    public function authorize(array $override = []): Response
    {
        $parameters = array_filter($override + [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => MockDeziFixture::REDIRECT_URI,
            'scope' => 'openid',
            'state' => $this->state,
            'nonce' => $this->nonce,
            'code_challenge' => Jose::base64Url(hash('sha256', $this->verifier, true)),
            'code_challenge_method' => 'S256',
            'prompt' => 'login',
            'max_age' => '0',
        ], static fn (?string $value): bool => $value !== null);
        $this->browser->request('GET', '/authorize?' . http_build_query($parameters));

        return $this->browser->getResponse();
    }

    public static function requestId(Response $loginPage): string
    {
        Assert::assertSame(200, $loginPage->getStatusCode(), (string) $loginPage->getContent());
        Assert::assertSame(1, preg_match('/name="request_id" value="([^"]+)"/', (string) $loginPage->getContent(), $m));

        return $m[1];
    }

    public function login(string $requestId, string $person, string $scenario = 'success', string $action = 'login'): Response
    {
        $this->browser->request('POST', '/authorize/login', [
            'request_id' => $requestId,
            'person' => $person,
            'scenario' => $scenario,
            'action' => $action,
        ]);

        return $this->browser->getResponse();
    }

    public function chooseProfile(string $requestId, string $profile, string $action = 'continue'): Response
    {
        $this->browser->request('POST', '/authorize/profile', [
            'request_id' => $requestId,
            'profile' => $profile,
            'action' => $action,
        ]);

        return $this->browser->getResponse();
    }

    /**
     * @return array<string, string> the query parameters of a redirect to JIP's callback
     */
    public static function callback(Response $response): array
    {
        Assert::assertSame(302, $response->getStatusCode(), (string) $response->getContent());
        $location = (string) $response->headers->get('Location');
        Assert::assertStringStartsWith(MockDeziFixture::REDIRECT_URI . '?', $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $parameters);

        /** @var array<string, string> $parameters */
        return $parameters;
    }

    /**
     * Logs in as $person with $scenario and returns the authorisation code.
     */
    public function code(string $person = 'anna', string $scenario = 'success', ?string $profile = null): string
    {
        $requestId = self::requestId($this->authorize());
        $response = $this->login($requestId, $person, $scenario);
        if ($profile !== null) {
            $response = $this->chooseProfile($requestId, $profile);
        }
        $callback = self::callback($response);
        Assert::assertSame($this->state, $callback['state'] ?? null);

        return $callback['code'] ?? throw new RuntimeException('no code in the callback');
    }

    /**
     * @param array<string, string|null> $override null removes a parameter
     */
    public function token(string $code, array $override = []): Response
    {
        $form = array_filter($override + [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => MockDeziFixture::REDIRECT_URI,
            'code_verifier' => $this->verifier,
            'client_id' => $this->clientId,
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->assertion(),
        ], static fn (?string $value): bool => $value !== null);
        $this->browser->request('POST', '/token', $form);

        return $this->browser->getResponse();
    }

    /**
     * @param array<string, mixed> $claims merged over the valid claims
     * @param array<string, mixed>|null $header replaces the valid header
     */
    public function assertion(array $claims = [], ?string $key = null, ?array $header = null, ?string $certificate = null): string
    {
        $now = time();
        $certificate ??= $this->fixture->signingCertificate;

        return Jose::sign(
            $claims + [
                'iss' => $this->clientId,
                'sub' => $this->clientId,
                'aud' => self::TOKEN_ENDPOINT,
                'iat' => $now,
                'exp' => $now + 60,
                'jti' => Jose::randomToken(),
            ],
            $key ?? $this->fixture->signingKey,
            $header ?? ['kid' => 'test-signing', 'x5t#S256' => self::thumbprint($certificate)],
        );
    }

    public static function thumbprint(string $certificate): string
    {
        return Jose::base64Url((string) openssl_x509_fingerprint($certificate, 'sha256', true));
    }

    /**
     * @return array<string, mixed> the successful token response
     */
    public function tokens(string $person = 'anna', string $scenario = 'success', ?string $profile = null): array
    {
        $response = $this->token($this->code($person, $scenario, $profile));
        Assert::assertSame(200, $response->getStatusCode(), (string) $response->getContent());

        return self::json($response);
    }

    public function userinfo(string $accessToken): Response
    {
        $this->browser->request('GET', '/userinfo', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken]);

        return $this->browser->getResponse();
    }

    public function keySet(string $path): JWKSet
    {
        $this->browser->request('GET', $path);

        $keys = JWKSet::createFromKeyData(self::json($this->browser->getResponse()));
        self::$keyAddresses ??= new WeakMap();
        self::$keyAddresses[$keys] = self::ISSUER . $path;

        return $keys;
    }

    /**
     * @return array<string, mixed>|null claims when headers and the RS256 signature match the supplied key set
     */
    public static function verify(string $jws, JWKSet $keys): ?array
    {
        try {
            $token = (new CompactSerializer())->unserialize($jws);
            $header = $token->getSignature(0)->getProtectedHeader();
            $kid = $header['kid'] ?? null;
            if (
                ($header['alg'] ?? null) !== 'RS256' || !is_string($kid) || !$keys->has($kid)
                || array_key_exists('crit', $header) || array_key_exists('b64', $header)
            ) {
                return null;
            }
            if (
                array_key_exists('jku', $header)
                && $header['jku'] !== (self::$keyAddresses[$keys] ?? null)
            ) {
                return null;
            }
            if (!(new JWSVerifier(new AlgorithmManager([new RS256()])))->verifyWithKey($token, $keys->get($kid), 0)) {
                return null;
            }
        } catch (Throwable) {
            return null;
        }
        $claims = json_decode((string) $token->getPayload(), true, 16, JSON_THROW_ON_ERROR);
        Assert::assertIsArray($claims);

        /** @var array<string, mixed> $claims */
        return $claims;
    }

    /**
     * @return array<string, mixed>
     */
    public static function header(string $compact): array
    {
        $header = json_decode((string) Jose::base64UrlDecode(explode('.', $compact)[0]), true, 16, JSON_THROW_ON_ERROR);
        Assert::assertIsArray($header);

        /** @var array<string, mixed> $header */
        return $header;
    }

    /**
     * @return array<string, mixed>
     */
    public static function payload(string $compact): array
    {
        $payload = json_decode((string) Jose::base64UrlDecode(explode('.', $compact)[1]), true, 16, JSON_THROW_ON_ERROR);
        Assert::assertIsArray($payload);

        /** @var array<string, mixed> $payload */
        return $payload;
    }

    /**
     * Decrypts a compact JWE with RSA-OAEP and A256CBC-HS512 using OpenSSL only (RFC 7516, RFC 7518 §5.2).
     */
    public function decrypt(string $jwe): string
    {
        $parts = explode('.', $jwe);
        Assert::assertCount(5, $parts);
        [$encodedHeader, $encryptedKey, $iv, $ciphertext, $tag] = array_map(
            static fn (string $part): string => (string) Jose::base64UrlDecode($part),
            $parts,
        );
        Assert::assertTrue(openssl_private_decrypt(
            $encryptedKey,
            $cek,
            $this->fixture->decryptionKeyPem,
            OPENSSL_PKCS1_OAEP_PADDING,
        ));
        Assert::assertIsString($cek);
        Assert::assertSame(64, strlen($cek));
        $aad = $parts[0];
        $mac = hash_hmac('sha512', $aad . $iv . $ciphertext . pack('J', strlen($aad) * 8), substr($cek, 0, 32), true);
        Assert::assertTrue(hash_equals(substr($mac, 0, 32), $tag), 'authentication tag');
        $plaintext = openssl_decrypt($ciphertext, 'aes-256-cbc', substr($cek, 32), OPENSSL_RAW_DATA, $iv);
        Assert::assertIsString($plaintext);
        unset($encodedHeader);

        return $plaintext;
    }

    /**
     * @return array<string, mixed>
     */
    public static function json(Response $response): array
    {
        $data = json_decode((string) $response->getContent(), true, 32, JSON_THROW_ON_ERROR);
        Assert::assertIsArray($data);

        /** @var array<string, mixed> $data */
        return $data;
    }
}
