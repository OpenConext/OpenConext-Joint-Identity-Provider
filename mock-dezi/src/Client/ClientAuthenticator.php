<?php

declare(strict_types=1);

namespace MockDezi\Client;

use MockDezi\Configuration\ClientRegistration;
use MockDezi\Configuration\MockConfiguration;
use MockDezi\Message\Jose;
use MockDezi\Store\State;

/**
 * Client authentication at the token endpoint (design §14, OpenID Connect Core §9).
 *
 * private_key_jwt: a compact JWS, RS256 only, header `x5t#S256` naming one of the client's registered signing
 * certificates, `iss` = `sub` = client ID, `aud` = the token endpoint, `exp` after now, `exp - iat` at most
 * max_client_assertion_lifetime_seconds, and a `jti` that was never used before.
 * PROVISIONAL: these are the design's assertion contents; what DEZI requires is open (design §10).
 * A client registered for `none` must send no assertion.
 */
final readonly class ClientAuthenticator
{
    public const string ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    /**
     * Returns null when the client is authenticated, or why it is not. Records the assertion's jti in $state.
     *
     * @param array<string, string> $form
     */
    public function authenticate(
        MockConfiguration $configuration,
        ClientRegistration $client,
        array $form,
        State $state,
        int $now,
    ): ?string {
        $type = $form['client_assertion_type'] ?? null;
        $assertion = $form['client_assertion'] ?? null;
        if ($client->authentication === ClientRegistration::AUTHENTICATION_NONE) {
            return $type === null && $assertion === null
                ? null
                : 'the client is registered for authentication "none" and sends no client assertion';
        }
        if ($type !== self::ASSERTION_TYPE) {
            return 'client_assertion_type must be ' . self::ASSERTION_TYPE;
        }
        if ($assertion === null || $assertion === '') {
            return 'client_assertion is missing';
        }

        $header = Jose::decodeJson(explode('.', $assertion)[0]);
        if ($header === null || substr_count($assertion, '.') !== 2) {
            return 'client_assertion is not a compact JWS';
        }
        if (($header['alg'] ?? null) !== 'RS256') {
            return 'client_assertion must be signed RS256';
        }
        $certificate = $this->registeredCertificate($client, $header['x5t#S256'] ?? null);
        if ($certificate === null) {
            return 'header x5t#S256 must name a registered signing certificate';
        }
        $verified = Jose::verifyRs256($assertion, $certificate);
        if ($verified === null) {
            return 'client_assertion signature does not verify with the registered certificate';
        }

        $claims = json_decode($verified[1], true, 16);
        if (!is_array($claims)) {
            return 'client_assertion payload is not a JSON object';
        }

        return $this->checkClaims($configuration, $client, $claims, $state, $now);
    }

    /**
     * @param array<mixed> $claims
     */
    private function checkClaims(
        MockConfiguration $configuration,
        ClientRegistration $client,
        array $claims,
        State $state,
        int $now,
    ): ?string {
        if (($claims['iss'] ?? null) !== $client->clientId || ($claims['sub'] ?? null) !== $client->clientId) {
            return 'iss and sub must equal the client ID';
        }
        $tokenEndpoint = $configuration->tokenEndpoint();
        $audience = $claims['aud'] ?? null;
        if ($audience !== $tokenEndpoint && $audience !== [$tokenEndpoint]) {
            return 'aud must equal the token endpoint ' . $tokenEndpoint;
        }
        $issuedAt = $claims['iat'] ?? null;
        $expiresAt = $claims['exp'] ?? null;
        if (!is_int($issuedAt) || !is_int($expiresAt)) {
            return 'iat and exp must be numbers';
        }
        $skew = $configuration->clockSkewSeconds;
        if ($expiresAt + $skew <= $now) {
            return 'client_assertion has expired';
        }
        if ($issuedAt > $now + $skew) {
            return 'iat lies in the future';
        }
        if ($expiresAt <= $issuedAt || $expiresAt - $issuedAt > $configuration->maxClientAssertionLifetimeSeconds) {
            return sprintf(
                'exp - iat must be between 1 and %d seconds',
                $configuration->maxClientAssertionLifetimeSeconds,
            );
        }
        $jti = $claims['jti'] ?? null;
        if (!is_string($jti) || $jti === '') {
            return 'jti is missing';
        }
        $key = $client->clientId . '|' . $jti;
        if (isset($state->usedAssertionIds[$key])) {
            return 'jti has been used before';
        }
        $state->usedAssertionIds[$key] = $expiresAt + $skew;

        return null;
    }

    private function registeredCertificate(ClientRegistration $client, mixed $thumbprint): ?string
    {
        if (!is_string($thumbprint)) {
            return null;
        }
        foreach ($client->signingCertificates as $certificate) {
            $fingerprint = openssl_x509_fingerprint($certificate, 'sha256', true);
            if ($fingerprint !== false && hash_equals(Jose::base64Url($fingerprint), $thumbprint)) {
                return $certificate;
            }
        }

        return null;
    }
}
