<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Oidc;

use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Oidc\OidcFailure;
use JointIdentityProvider\Oidc\OidcFailureType;
use JointIdentityProvider\Tests\Support\ConfigurationFixture as Fixture;
use JointIdentityProvider\Tests\Support\OidcFixture;
use JointIdentityProvider\Tests\Support\TestProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * The token request with `private_key_jwt` or `none` and the token-response checks (design §14, §18
 * "Client authentication").
 */
final class TokenClientTest extends TestCase
{
    private OidcFixture $oidc;

    protected function setUp(): void
    {
        $this->oidc = new OidcFixture();
    }

    protected function tearDown(): void
    {
        $this->oidc->remove();
    }

    public function test_the_token_request_carries_a_fresh_signed_client_assertion(): void
    {
        $configuration = $this->oidc->configuration();
        $this->exchange($configuration);
        $first = $this->oidc->provider->lastTokenRequestForm();
        $this->exchange($configuration);
        $second = $this->oidc->provider->lastTokenRequestForm();

        self::assertSame([
            'grant_type' => 'authorization_code',
            'code' => 'the-code',
            'redirect_uri' => 'https://jip.dev.openconext.local/oidc/callback',
            'code_verifier' => 'the-verifier',
            'client_id' => TestProvider::CLIENT_ID,
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        ], array_diff_key($first, ['client_assertion' => true]));

        [$encodedHeader, $encodedClaims, $signature] = explode('.', $first['client_assertion']);
        $certificate = (string) file_get_contents($this->oidc->configFixture->directory . '/signing.crt');
        self::assertSame(1, openssl_verify(
            $encodedHeader . '.' . $encodedClaims,
            self::decode($signature),
            $certificate,
            OPENSSL_ALGO_SHA256,
        ));

        $header = self::json($encodedHeader);
        self::assertSame(['alg', 'x5t#S256'], array_keys($header));
        self::assertSame('RS256', $header['alg']);
        $x509 = openssl_x509_read($certificate);
        self::assertNotFalse($x509);
        self::assertSame(TestProvider::b64((string) openssl_x509_fingerprint($x509, 'sha256', true)), $header['x5t#S256']);

        $claims = self::json($encodedClaims);
        $now = $this->oidc->clock->now()->getTimestamp();
        self::assertSame(TestProvider::CLIENT_ID, $claims['iss']);
        self::assertSame(TestProvider::CLIENT_ID, $claims['sub']);
        self::assertSame(TestProvider::TOKEN, $claims['aud']);
        self::assertSame($now, $claims['iat']);
        self::assertSame($now + 60, $claims['exp']);
        self::assertIsString($claims['jti']);
        self::assertGreaterThanOrEqual(43, strlen($claims['jti']));

        self::assertNotSame(self::json(explode('.', $second['client_assertion'])[1])['jti'], $claims['jti']);
    }

    public function test_a_configured_kid_goes_into_the_assertion_header(): void
    {
        $configuration = $this->oidc->configuration([
            [['provider', 'clients', 'ggd', 'signing_key', 'kid'], 'signing-2026'],
        ]);

        $this->exchange($configuration);

        $header = self::json(explode('.', $this->oidc->provider->lastTokenRequestForm()['client_assertion'])[0]);
        self::assertSame(['alg', 'kid', 'x5t#S256'], array_keys($header));
        self::assertSame('signing-2026', $header['kid']);
    }

    public function test_a_none_client_sends_no_assertion(): void
    {
        $configuration = $this->oidc->configuration([
            [['provider', 'clients', 'ggd', 'authentication'], 'none'],
            [['provider', 'clients', 'ggd', 'signing_key'], Fixture::ABSENT],
        ]);

        $this->exchange($configuration);

        $form = $this->oidc->provider->lastTokenRequestForm();
        self::assertArrayNotHasKey('client_assertion', $form);
        self::assertArrayNotHasKey('client_assertion_type', $form);
    }

    public function test_an_unlisted_method_fails_before_any_token_request(): void
    {
        $this->oidc->provider->discovery['token_endpoint_auth_methods_supported'] = ['none'];

        self::assertSame(OidcFailureType::AuthenticationMethodNotSupported, $this->failure()->type);
        self::assertSame(0, $this->oidc->provider->countRequests([TestProvider::TOKEN]));
    }

    public function test_invalid_client_has_its_own_type_and_no_second_request_follows(): void
    {
        $this->answerToken(TestProvider::json(['error' => 'invalid_client'], 401));

        self::assertSame(OidcFailureType::ClientAuthenticationRefused, $this->failure()->type);
        self::assertSame(1, $this->oidc->provider->countRequests([TestProvider::TOKEN]));
    }

    /**
     * @param array<string, mixed> $options
     */
    #[DataProvider('failedAnswers')]
    public function test_failed_answers(string $body, array $options, OidcFailureType $type): void
    {
        $this->answerToken(new MockResponse($body, $options));

        self::assertSame($type, $this->failure()->type);
        self::assertSame(1, $this->oidc->provider->countRequests([TestProvider::TOKEN]));
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>, OidcFailureType}>
     */
    public static function failedAnswers(): iterable
    {
        $ok = '{"token_type":"Bearer","access_token":"a","id_token":"b"}';

        yield 'server error' => ['', ['http_code' => 500], OidcFailureType::TokenRequestUnavailable];
        yield 'redirect' => ['', ['http_code' => 307, 'response_headers' => ['Location' => TestProvider::TOKEN]], OidcFailureType::TokenRequestUnavailable];
        yield 'invalid body' => ['<html>', [], OidcFailureType::TokenRequestUnavailable];
        yield 'invalid_grant' => ['{"error":"invalid_grant"}', ['http_code' => 400], OidcFailureType::TokenRequestRefused];
        yield 'another 2xx' => [$ok, ['http_code' => 201], OidcFailureType::TokenResponseInvalid];
        yield 'not bearer' => ['{"token_type":"mac","access_token":"a","id_token":"b"}', [], OidcFailureType::TokenResponseInvalid];
        yield 'no id_token' => ['{"token_type":"Bearer","access_token":"a"}', [], OidcFailureType::TokenResponseInvalid];
        yield 'no access_token' => ['{"token_type":"Bearer","id_token":"b"}', [], OidcFailureType::TokenResponseInvalid];
    }

    private function answerToken(MockResponse $response): void
    {
        $this->oidc->provider->answers[TestProvider::TOKEN] = static fn (): MockResponse => $response;
    }

    private function exchange(JipConfiguration $configuration): void
    {
        $this->oidc->tokens()->exchange(
            $this->oidc->metadata()->load($configuration->provider),
            $configuration->provider->oidc->clients['ggd'],
            'the-code',
            'the-verifier',
        );
    }

    private function failure(): OidcFailure
    {
        try {
            $this->exchange($this->oidc->configuration());
        } catch (OidcFailure $failure) {
            return $failure;
        }

        self::fail('The token exchange succeeded.');
    }

    /**
     * @return array<string, mixed>
     */
    private static function json(string $segment): array
    {
        $data = json_decode(self::decode($segment), true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($data);

        /** @var array<string, mixed> $data */
        return $data;
    }

    private static function decode(string $segment): string
    {
        return (string) base64_decode(strtr($segment, '-_', '+/'), true);
    }
}
