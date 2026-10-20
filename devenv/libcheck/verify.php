<?php

declare(strict_types=1);

/*
 * Executable check of the JOSE/OIDC library choice for the JointIdentityProvider (JIP) (design §14, §19).
 * Uses web-token/jwt-library and symfony/http-client only. A MockHttpClient plays a minimal
 * OpenID provider so that every request the connector would send is really built, sent and parsed.
 * The provider data below is harness data, not DEZI's message format.
 *
 * Usage: php verify.php [--live]
 *   --live  also fetches DEZI acceptance discovery with TLS 1.3 enforced and redirects disabled.
 */

require __DIR__ . '/vendor/autoload.php';

use Composer\InstalledVersions;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Serializer\CompactSerializer as JweCompact;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer as JwsCompact;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

$passed = 0;
$failed = 0;

function check(string $label, callable $test): void
{
    global $passed, $failed;
    try {
        $result = $test();
        if ($result !== true) {
            throw new RuntimeException(is_string($result) ? $result : 'returned ' . var_export($result, true));
        }
        printf("  PASS  %s\n", $label);
        $passed++;
    } catch (Throwable $e) {
        printf("  FAIL  %s\n        %s: %s\n", $label, $e::class, $e->getMessage());
        $failed++;
    }
}

function rejects(callable $test): bool
{
    try {
        $result = $test();
    } catch (Throwable) {
        return true;
    }

    return $result === false;
}

function b64u(string $bin): string
{
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

/** @return array{JWK, string} private JWK and PEM certificate */
function rsaKeyWithCertificate(string $kid, string $use, string $alg): array
{
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $csr = openssl_csr_new(['commonName' => $kid], $key, ['digest_alg' => 'sha256']);
    $cert = openssl_csr_sign($csr, null, $key, 30, ['digest_alg' => 'sha256']);
    openssl_x509_export($cert, $certPem);
    openssl_pkey_export($key, $keyPem);

    return [JWKFactory::createFromKey($keyPem, null, ['kid' => $kid, 'use' => $use, 'alg' => $alg]), $certPem];
}

function x5tS256(string $certPem): string
{
    return b64u(openssl_x509_fingerprint($certPem, 'sha256', true));
}

function signJws(array $claims, JWK $key, array $header): string
{
    $jws = (new JWSBuilder(new AlgorithmManager([new RS256()])))->create()
        ->withPayload(json_encode($claims, JSON_THROW_ON_ERROR))
        ->addSignature($key, $header)
        ->build();

    return (new JwsCompact())->serialize($jws, 0);
}

/** Verifies a compact JWS against the given key set with RS256 only; returns the claims. */
function verifyRs256(string $token, JWKSet $keys): array
{
    $jws = (new JwsCompact())->unserialize($token);
    (new HeaderCheckerManager([new AlgorithmChecker(['RS256'], true)], [new JWSTokenSupport()]))
        ->check($jws, 0, ['alg']);
    if (!(new JWSVerifier(new AlgorithmManager([new RS256()])))->verifyWithKeySet($jws, $keys, 0)) {
        throw new RuntimeException('signature does not verify');
    }

    return json_decode($jws->getPayload(), true, 512, JSON_THROW_ON_ERROR);
}

$clock = new NativeClock();
$skew = 60;

// web-token's RSA-OAEP uses brick/math; without gmp one 2048-bit decryption took ~43 s on PHP 8.5.11.
if (!extension_loaded('gmp')) {
    fwrite(STDERR, "ext-gmp is required (RSA-OAEP is unusably slow without it). Run with -d extension=/path/to/gmp.so\n");
    exit(2);
}

echo "Runtime\n";
printf("  PHP %s; ext-openssl %s; gmp %s; bcmath %s\n", PHP_VERSION, OPENSSL_VERSION_TEXT,
    extension_loaded('gmp') ? 'yes' : 'no', extension_loaded('bcmath') ? 'yes' : 'no');
foreach (['web-token/jwt-library', 'spomky-labs/pki-framework', 'brick/math', 'symfony/http-client', 'symfony/clock'] as $pkg) {
    printf("  %s %s\n", $pkg, InstalledVersions::getPrettyVersion($pkg));
}

// Keys: provider ID-token key, provider envelope key (separate address), client signing key, two client decryption keys.
[$opIdKey] = rsaKeyWithCertificate('op-id-token', 'sig', 'RS256');
[$opEnvKey] = rsaKeyWithCertificate('op-envelope', 'sig', 'RS256');
[$clientSigKey, $clientSigCert] = rsaKeyWithCertificate('client-sig-2026', 'sig', 'RS256');
[$decNew] = rsaKeyWithCertificate('client-enc-new', 'enc', 'RSA-OAEP');
[$decOld] = rsaKeyWithCertificate('client-enc-old', 'enc', 'RSA-OAEP');
[$attackerKey] = rsaKeyWithCertificate('op-id-token', 'sig', 'RS256');

$issuer = 'https://op.libcheck.test';
$tokenEndpoint = $issuer . '/token';
$clientId = 'libcheck-client';
$redirectUri = 'https://connector.libcheck.test/oidc/callback';
$idTokenKeys = new JWKSet([$opIdKey->toPublic()]);
$envelopeKeys = new JWKSet([$opEnvKey->toPublic()]);

// ---------------------------------------------------------------- minimal provider (harness only)
$codes = [];
$seenJti = [];
$accessTokens = [];
$userinfoEncryptFor = $decNew;
$userinfoAlgorithms = [new RSAOAEP(), new A256CBCHS512()];
$userinfoHeader = ['alg' => 'RSA-OAEP', 'enc' => 'A256CBC-HS512'];

$provider = function (string $method, string $url, array $options) use (
    &$codes, &$seenJti, &$accessTokens, &$userinfoEncryptFor, &$userinfoAlgorithms, &$userinfoHeader,
    $issuer, $tokenEndpoint, $clientId, $redirectUri, $clientSigKey, $clientSigCert, $opIdKey, $opEnvKey
): MockResponse {
    $error = static fn (string $code, int $status = 400) => new MockResponse(
        json_encode(['error' => $code]), ['http_code' => $status, 'response_headers' => ['content-type' => 'application/json']]
    );

    if ($method === 'POST' && $url === $tokenEndpoint) {
        parse_str($options['body'], $form);
        if (($form['client_assertion_type'] ?? '') !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
            return $error('invalid_client', 401);
        }
        try {
            $jws = (new JwsCompact())->unserialize($form['client_assertion'] ?? '');
            $header = $jws->getSignature(0)->getProtectedHeader();
            if (($header['alg'] ?? '') !== 'RS256' || ($header['x5t#S256'] ?? '') !== x5tS256($clientSigCert)) {
                return $error('invalid_client', 401);
            }
            $claims = verifyRs256($form['client_assertion'], new JWKSet([$clientSigKey->toPublic()]));
        } catch (Throwable) {
            return $error('invalid_client', 401);
        }
        $now = time();
        if ($claims['iss'] !== $clientId || $claims['sub'] !== $clientId || $claims['aud'] !== $tokenEndpoint
            || $claims['exp'] < $now || $claims['exp'] - $claims['iat'] > 60 || isset($seenJti[$claims['jti']])) {
            return $error('invalid_client', 401);
        }
        $seenJti[$claims['jti']] = true;

        $code = $codes[$form['code'] ?? ''] ?? null;
        unset($codes[$form['code'] ?? '']);
        if ($form['grant_type'] !== 'authorization_code' || $code === null || $form['redirect_uri'] !== $redirectUri
            || b64u(hash('sha256', $form['code_verifier'] ?? '', true)) !== $code['challenge']) {
            return $error('invalid_grant');
        }
        $access = b64u(random_bytes(32));
        $accessTokens[$access] = true;
        $idToken = signJws([
            'iss' => $issuer, 'sub' => 'pairwise-sub', 'aud' => $clientId, 'iat' => $now, 'exp' => $now + 300,
            'auth_time' => $code['auth_time'], 'nonce' => $code['nonce'],
        ], $opIdKey, ['alg' => 'RS256', 'kid' => $opIdKey->get('kid')]);

        return new MockResponse(json_encode([
            'access_token' => $access, 'token_type' => 'Bearer', 'expires_in' => 300, 'id_token' => $idToken,
        ]), ['response_headers' => ['content-type' => 'application/json']]);
    }

    if ($method === 'GET' && $url === $issuer . '/userinfo') {
        $bearer = null;
        foreach ($options['headers'] as $h) {
            if (str_starts_with(strtolower($h), 'authorization: bearer ')) {
                $bearer = substr($h, strlen('authorization: bearer '));
            }
        }
        if ($bearer === null || !isset($accessTokens[$bearer])) {
            return $error('invalid_token', 401);
        }
        $now = time();
        $envelope = signJws(['iss' => 'envelope-issuer', 'aud' => $clientId, 'iat' => $now, 'exp' => $now + 300,
            'verklaring_id' => '3f1c2c3e-8a7b-4d2e-9f00-1a2b3c4d5e6f'], $opEnvKey, ['alg' => 'RS256', 'kid' => $opEnvKey->get('kid')]);
        $jwe = (new JWEBuilder(new AlgorithmManager($userinfoAlgorithms)))->create()
            ->withPayload($envelope)
            ->withSharedProtectedHeader($userinfoHeader + ['kid' => $userinfoEncryptFor->get('kid')])
            ->addRecipient($userinfoEncryptFor->toPublic())
            ->build();

        return new MockResponse((new JweCompact())->serialize($jwe, 0), ['response_headers' => ['content-type' => 'application/jwt']]);
    }

    return $error('not_found', 404);
};

// The provider's authorisation endpoint, after a successful user login.
$authorize = function (array $query) use (&$codes): string {
    $code = b64u(random_bytes(32));
    $codes[$code] = ['challenge' => $query['code_challenge'], 'nonce' => $query['nonce'], 'auth_time' => time()];

    return $code;
};

// ---------------------------------------------------------------- connector-side helpers under test
$http = new MockHttpClient($provider);

$clientAssertion = function (?JWK $key = null, ?string $aud = null, int $lifetime = 60, ?string $jti = null) use ($clientSigKey, $clientSigCert, $clientId, $tokenEndpoint): string {
    $now = time();

    return signJws(
        ['iss' => $clientId, 'sub' => $clientId, 'aud' => $aud ?? $tokenEndpoint, 'iat' => $now, 'exp' => $now + $lifetime, 'jti' => $jti ?? b64u(random_bytes(32))],
        $key ?? $clientSigKey,
        ['alg' => 'RS256', 'kid' => $clientSigKey->get('kid'), 'x5t#S256' => x5tS256($clientSigCert)]
    );
};

$tokenRequest = function (string $code, string $verifier, ?string $assertion = null) use ($http, $tokenEndpoint, $redirectUri, $clientId, $clientAssertion) {
    return $http->request('POST', $tokenEndpoint, [
        'body' => [
            'grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => $redirectUri,
            'code_verifier' => $verifier, 'client_id' => $clientId,
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $assertion ?? $clientAssertion(),
        ],
        'max_redirects' => 0,
    ]);
};

$validateIdToken = function (string $idToken, string $expectedIssuer, string $nonce, int $attemptStart) use ($idTokenKeys, $clientId, $clock, $skew): array {
    $claims = verifyRs256($idToken, $idTokenKeys);
    (new ClaimCheckerManager([
        new IssuerChecker([$expectedIssuer]),
        new AudienceChecker($clientId),
        new ExpirationTimeChecker($clock, $skew),
        new IssuedAtChecker($clock, $skew),
    ]))->check($claims, ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce']);
    // Outside the library: nonce, untrusted audiences, auth_time window (§14 ID token row).
    if (!is_string($claims['nonce']) || !hash_equals($nonce, $claims['nonce'])) {
        throw new RuntimeException('nonce mismatch');
    }
    foreach ((array) $claims['aud'] as $aud) {
        if ($aud !== $clientId) {
            throw new RuntimeException('untrusted audience');
        }
    }
    if (!is_int($claims['auth_time']) || $claims['auth_time'] < $attemptStart - $skew || $claims['auth_time'] > time() + $skew) {
        throw new RuntimeException('auth_time outside the attempt window');
    }

    return $claims;
};

/** Decrypts with the configured keys, newest first, trying a key whose kid matches the header first. */
$decryptUserinfo = function (string $compact, array $decryptionKeys): string {
    $jwe = (new JweCompact())->unserialize($compact);
    $header = $jwe->getSharedProtectedHeader();
    if (($header['alg'] ?? null) !== 'RSA-OAEP' || ($header['enc'] ?? null) !== 'A256CBC-HS512') {
        throw new RuntimeException('unexpected JWE alg/enc');
    }
    usort($decryptionKeys, static fn (JWK $a, JWK $b) => (int) ($b->get('kid') === ($header['kid'] ?? null)) <=> (int) ($a->get('kid') === ($header['kid'] ?? null)));
    $decrypter = new JWEDecrypter(new AlgorithmManager([new RSAOAEP(), new A256CBCHS512()]));
    if (!$decrypter->decryptUsingKeySet($jwe, new JWKSet($decryptionKeys), 0)) {
        throw new RuntimeException('no configured key decrypts the response');
    }

    return $jwe->getPayload();
};

// ---------------------------------------------------------------- PKCE
echo "\nPKCE S256 (RFC 7636)\n";
check('RFC 7636 appendix B test vector', fn () => b64u(hash('sha256', 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', true)) === 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
$verifier = b64u(random_bytes(32));
check('generated verifier is 43 unreserved characters', fn () => preg_match('/^[A-Za-z0-9\-._~]{43}$/', $verifier) === 1);

// ---------------------------------------------------------------- full code flow
echo "\nAuthorization code flow with private_key_jwt (RS256), ID token, encrypted UserInfo\n";
$attemptStart = time();
$state = b64u(random_bytes(32));
$nonce = b64u(random_bytes(32));
$authUrl = $issuer . '/authorize?' . http_build_query([
    'response_type' => 'code', 'client_id' => $clientId, 'redirect_uri' => $redirectUri, 'scope' => 'openid',
    'state' => $state, 'nonce' => $nonce, 'code_challenge' => b64u(hash('sha256', $verifier, true)),
    'code_challenge_method' => 'S256', 'prompt' => 'login', 'max_age' => 0,
], '', '&', PHP_QUERY_RFC3986);
parse_str(parse_url($authUrl, PHP_URL_QUERY), $sent);
check('authorisation request carries code, PKCE S256, state, nonce, prompt=login, max_age=0',
    fn () => $sent['response_type'] === 'code' && $sent['code_challenge_method'] === 'S256' && $sent['prompt'] === 'login' && $sent['max_age'] === '0');

$code = $authorize($sent);
$tokenResponse = $tokenRequest($code, $verifier);
check('token endpoint accepts private_key_jwt assertion and PKCE verifier (HTTP 200)', fn () => $tokenResponse->getStatusCode() === 200);
$tokens = $tokenResponse->toArray(false);
check('token response: token_type Bearer, id_token and access_token present',
    fn () => ($tokens['token_type'] ?? '') === 'Bearer' && isset($tokens['id_token'], $tokens['access_token']));
check('ID token verifies (RS256, approved key set, iss, aud, exp, iat, nonce, auth_time)',
    fn () => $validateIdToken($tokens['id_token'], $issuer, $nonce, $attemptStart)['sub'] === 'pairwise-sub');

$userinfo = $http->request('GET', $issuer . '/userinfo', ['auth_bearer' => $tokens['access_token'], 'max_redirects' => 0]);
$envelopeJws = $decryptUserinfo($userinfo->getContent(), [$decNew, $decOld]);
check('UserInfo JWE RSA-OAEP + A256CBC-HS512 decrypts', fn () => substr_count($envelopeJws, '.') === 2);
check('nested envelope JWS verifies with the envelope key set only',
    fn () => verifyRs256($envelopeJws, $envelopeKeys)['verklaring_id'] === '3f1c2c3e-8a7b-4d2e-9f00-1a2b3c4d5e6f');
check('envelope JWS does not verify with the ID-token key set', fn () => rejects(fn () => verifyRs256($envelopeJws, $idTokenKeys)));

// ---------------------------------------------------------------- client authentication refusals
echo "\nprivate_key_jwt refusals (provider side) and assertion shape\n";
$assertion = $clientAssertion();
$parts = (new JwsCompact())->unserialize($assertion);
$h = $parts->getSignature(0)->getProtectedHeader();
$c = json_decode($parts->getPayload(), true);
check('assertion header: alg RS256, kid, x5t#S256 = SHA-256 of certificate DER',
    fn () => $h['alg'] === 'RS256' && $h['kid'] === 'client-sig-2026' && $h['x5t#S256'] === x5tS256($clientSigCert));
check('assertion claims: iss = sub = client_id, aud = token_endpoint, exp - iat = 60, jti',
    fn () => $c['iss'] === $clientId && $c['sub'] === $clientId && $c['aud'] === $tokenEndpoint && $c['exp'] - $c['iat'] === 60 && strlen($c['jti']) >= 43);
check('jti differs per assertion', fn () => json_decode((new JwsCompact())->unserialize($clientAssertion())->getPayload(), true)['jti'] !== $c['jti']);
$jti = b64u(random_bytes(16));
$tokenRequest($authorize($sent), $verifier, $clientAssertion(jti: $jti))->getStatusCode();
check('repeated jti refused (401)', fn () => $tokenRequest($authorize($sent), $verifier, $clientAssertion(jti: $jti))->getStatusCode() === 401);
check('wrong aud refused (401)', fn () => $tokenRequest($authorize($sent), $verifier, $clientAssertion(aud: $issuer))->getStatusCode() === 401);
check('assertion signed with another key refused (401)', fn () => $tokenRequest($authorize($sent), $verifier, $clientAssertion(key: $attackerKey))->getStatusCode() === 401);
check('expired assertion refused (401)', fn () => $tokenRequest($authorize($sent), $verifier, $clientAssertion(lifetime: -120))->getStatusCode() === 401);
check('wrong PKCE verifier refused (400)', fn () => $tokenRequest($authorize($sent), b64u(random_bytes(32)))->getStatusCode() === 400);
check('web-token certificate import names the thumbprint "x5t#256", not "x5t#S256": the connector sets the header itself',
    fn () => JWKFactory::createFromCertificate($clientSigCert)->has('x5t#256') && !JWKFactory::createFromCertificate($clientSigCert)->has('x5t#S256'));

// ---------------------------------------------------------------- JWS refusals
echo "\nJWS verification refusals\n";
$now = time();
$good = ['iss' => $issuer, 'sub' => 's', 'aud' => $clientId, 'iat' => $now, 'exp' => $now + 300, 'auth_time' => $now, 'nonce' => $nonce];
$noneToken = (new JwsCompact())->serialize((new JWSBuilder(new AlgorithmManager([new None()])))->create()
    ->withPayload(json_encode($good))->addSignature(JWKFactory::createNoneKey(), ['alg' => 'none'])->build(), 0);
check('alg "none" refused', fn () => rejects(fn () => verifyRs256($noneToken, $idTokenKeys)));
$hmacKey = JWKFactory::createFromSecret($opIdKey->toPublic()->get('n'));
$hsToken = (new JwsCompact())->serialize((new JWSBuilder(new AlgorithmManager([new HS256()])))->create()
    ->withPayload(json_encode($good))->addSignature($hmacKey, ['alg' => 'HS256'])->build(), 0);
check('HS256 (algorithm confusion with the public key) refused', fn () => rejects(fn () => verifyRs256($hsToken, $idTokenKeys)));
check('same kid, unapproved key refused', fn () => rejects(fn () => verifyRs256(signJws($good, $attackerKey, ['alg' => 'RS256', 'kid' => 'op-id-token']), $idTokenKeys)));
check('jku header is not followed: verification uses only the supplied key set',
    fn () => rejects(fn () => verifyRs256(signJws($good, $attackerKey, ['alg' => 'RS256', 'jku' => 'https://attacker.test/jwks']), $idTokenKeys)));
$signed = signJws($good, $opIdKey, ['alg' => 'RS256']);
[$h64, , $s64] = explode('.', $signed);
check('tampered payload refused', fn () => rejects(fn () => verifyRs256($h64 . '.' . b64u(json_encode(['sub' => 'other'] + $good)) . '.' . $s64, $idTokenKeys)));
check('wrong issuer refused', fn () => rejects(fn () => $validateIdToken(signJws(['iss' => 'https://other.test'] + $good, $opIdKey, ['alg' => 'RS256']), $issuer, $nonce, $now)));
check('wrong nonce refused', fn () => rejects(fn () => $validateIdToken(signJws(['nonce' => 'x'] + $good, $opIdKey, ['alg' => 'RS256']), $issuer, $nonce, $now)));
check('auth_time before the attempt start refused', fn () => rejects(fn () => $validateIdToken(signJws(['auth_time' => $now - 3600] + $good, $opIdKey, ['alg' => 'RS256']), $issuer, $nonce, $now)));
check('extra untrusted audience refused', fn () => rejects(fn () => $validateIdToken(signJws(['aud' => [$clientId, 'other']] + $good, $opIdKey, ['alg' => 'RS256']), $issuer, $nonce, $now)));
check('library time checkers reject digit-string exp/nbf (revocation-list conversion stays in the profile, §16)',
    fn () => rejects(fn () => (new ClaimCheckerManager([new ExpirationTimeChecker($clock)]))->check(['exp' => (string) ($now + 300)]))
        && rejects(fn () => (new ClaimCheckerManager([new NotBeforeChecker($clock)]))->check(['nbf' => (string) $now])));

// ---------------------------------------------------------------- JWE refusals and key rotation
echo "\nJWE refusals and decryption-key rotation\n";
$fetchUserinfo = function () use ($http, $issuer, $tokenRequest, $authorize, $sent, $verifier): string {
    $t = $tokenRequest($authorize($sent), $verifier)->toArray();

    return $http->request('GET', $issuer . '/userinfo', ['auth_bearer' => $t['access_token']])->getContent();
};
$userinfoEncryptFor = $decOld;
$oldKeyResponse = $fetchUserinfo();
check('response for the previous key decrypts while both keys are configured', fn () => strlen($decryptUserinfo($oldKeyResponse, [$decNew, $decOld])) > 0);
check('response for the previous key fails once that key is removed', fn () => rejects(fn () => $decryptUserinfo($oldKeyResponse, [$decNew])));
$userinfoAlgorithms = [new RSAOAEP256(), new A256CBCHS512()];
$userinfoHeader = ['alg' => 'RSA-OAEP-256', 'enc' => 'A256CBC-HS512'];
$userinfoEncryptFor = new JWK(['alg' => 'RSA-OAEP-256'] + $decNew->all());
check('alg RSA-OAEP-256 refused', fn () => rejects(fn () => $decryptUserinfo($fetchUserinfo(), [$decNew])));
$userinfoAlgorithms = [new RSAOAEP(), new A128GCM()];
$userinfoHeader = ['alg' => 'RSA-OAEP', 'enc' => 'A128GCM'];
$userinfoEncryptFor = $decNew;
check('enc A128GCM refused', fn () => rejects(fn () => $decryptUserinfo($fetchUserinfo(), [$decNew])));
$userinfoAlgorithms = [new RSAOAEP(), new A256CBCHS512()];
$userinfoHeader = ['alg' => 'RSA-OAEP', 'enc' => 'A256CBC-HS512'];
check('library itself refuses an enc outside its algorithm manager',
    fn () => rejects(function () use ($decNew) {
        $jwe = (new JWEBuilder(new AlgorithmManager([new RSAOAEP(), new A128GCM()])))->create()->withPayload('x')
            ->withSharedProtectedHeader(['alg' => 'RSA-OAEP', 'enc' => 'A128GCM'])->addRecipient($decNew->toPublic())->build();

        return (new JWEDecrypter(new AlgorithmManager([new RSAOAEP(), new A256CBCHS512()])))->decryptUsingKey($jwe, $decNew, 0);
    }));

// ---------------------------------------------------------------- cost of RSA without gmp/bcmath
echo "\nCost on this runtime\n";
$t = hrtime(true);
for ($i = 0; $i < 20; $i++) {
    verifyRs256($signed, $idTokenKeys);
}
printf("  RS256 verify: %.1f ms each\n", (hrtime(true) - $t) / 20 / 1e6);
$t = hrtime(true);
for ($i = 0; $i < 5; $i++) {
    $decryptUserinfo($oldKeyResponse, [$decOld]);
}
printf("  RSA-OAEP + A256CBC-HS512 decrypt: %.1f ms each\n", (hrtime(true) - $t) / 5 / 1e6);

// ---------------------------------------------------------------- optional live TLS 1.3 check
if (in_array('--live', $argv, true)) {
    echo "\nLive: DEZI acceptance discovery with TLS 1.3 minimum and no redirects (read-only)\n";
    $live = HttpClient::create(['crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT, 'max_redirects' => 0, 'timeout' => 10]);
    $r = $live->request('GET', 'https://acceptatie.auth.dezi.nl/.well-known/openid-configuration');
    check('HTTP 200 over TLS 1.3', function () use ($r) {
        $status = $r->getStatusCode();
        preg_match('/SSL connection using (TLSv[0-9.]+)/', (string) $r->getInfo('debug'), $m);
        printf("        status %d, %s\n", $status, $m[1] ?? 'TLS version not reported');

        return $status === 200 && ($m[1] ?? '') === 'TLSv1.3';
    });
    $d = $r->toArray(false);
    printf("        issuer %s\n        jwks_uri %s\n        token_endpoint_auth_methods_supported %s\n        code_challenge_methods_supported %s\n",
        $d['issuer'] ?? '-', $d['jwks_uri'] ?? '-', json_encode($d['token_endpoint_auth_methods_supported'] ?? null), json_encode($d['code_challenge_methods_supported'] ?? null));
}

printf("\n%d passed, %d failed\n", $passed, $failed);
exit($failed === 0 ? 0 : 1);
