<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Oidc;

use JointIdentityProvider\Oidc\Configuration\ClientAuthentication;
use JointIdentityProvider\Oidc\OidcFailure;
use JointIdentityProvider\Oidc\OidcFailureType;
use JointIdentityProvider\Tests\Support\OidcFixture;
use JointIdentityProvider\Tests\Support\TestProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Discovery (design §14 "DEZI's keys and metadata", §18 "Keys").
 */
final class MetadataProviderTest extends TestCase
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

    public function test_metadata_comes_from_the_issuers_well_known_address_and_is_kept(): void
    {
        $provider = $this->oidc->configuration()->provider;

        $metadata = $this->oidc->metadata()->load($provider->oidc, $provider->trust);
        $this->oidc->metadata()->load($provider->oidc, $provider->trust);

        self::assertSame(TestProvider::AUTHORIZE, $metadata->authorizationEndpoint);
        self::assertSame(TestProvider::TOKEN, $metadata->tokenEndpoint);
        self::assertSame([TestProvider::DISCOVERY], array_column($this->oidc->provider->requests, 'url'));

        $this->oidc->clock->sleep(3600);
        $this->oidc->metadata()->load($provider->oidc, $provider->trust);
        self::assertSame(2, $this->oidc->provider->countRequests([TestProvider::DISCOVERY]));
    }

    /**
     * @param array<string, mixed> $changes
     */
    #[DataProvider('invalidDocuments')]
    public function test_invalid_metadata_is_refused(array $changes, string $detail): void
    {
        $this->oidc->provider->discovery = array_filter(
            $changes + $this->oidc->provider->discovery,
            static fn (mixed $value): bool => $value !== null,
        );

        $failure = $this->load();

        self::assertSame(OidcFailureType::DiscoveryInvalid, $failure->type);
        self::assertStringContainsString($detail, $failure->detail);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidDocuments(): iterable
    {
        yield 'another issuer' => [['issuer' => 'https://other.example'], 'issuer differs'];
        yield 'no issuer' => [['issuer' => null], 'issuer differs'];
        yield 'another jwks_uri' => [['jwks_uri' => TestProvider::STATEMENT_JWKS], 'jwks_uri differs'];
        yield 'an http token endpoint' => [['token_endpoint' => 'http://mock-dezi.dev.openconext.local/token'], 'endpoint'];
        yield 'no authorization endpoint' => [['authorization_endpoint' => null], 'endpoint'];
        yield 'methods not a list' => [['token_endpoint_auth_methods_supported' => 'private_key_jwt'], 'not a list'];
    }

    public function test_kept_metadata_is_checked_again_against_the_current_configuration(): void
    {
        $provider = $this->oidc->configuration()->provider;
        $this->oidc->metadata()->load($provider->oidc, $provider->trust);
        $changed = $this->oidc->configuration([
            [['provider', 'approved_key_addresses', 'id_token'], 'https://mock-dezi.dev.openconext.local/other-jwks.json'],
        ]);

        $this->expectException(OidcFailure::class);
        try {
            $this->oidc->metadata()->load($changed->provider->oidc, $changed->provider->trust);
        } finally {
            self::assertSame(2, $this->oidc->provider->countRequests([TestProvider::DISCOVERY]));
        }
    }

    public function test_no_answer_and_a_client_error_have_their_own_types(): void
    {
        $this->oidc->provider->answers[TestProvider::DISCOVERY] = static fn (): MockResponse => new MockResponse('', [
            'http_code' => 301,
            'response_headers' => ['Location' => 'https://elsewhere.example/'],
        ]);
        self::assertSame(OidcFailureType::DiscoveryUnavailable, $this->load()->type);

        $this->oidc->clock->sleep(60);
        $this->oidc->provider->answers[TestProvider::DISCOVERY] = static fn (): MockResponse => new MockResponse('<html>');
        self::assertSame(OidcFailureType::DiscoveryUnavailable, $this->load()->type);

        $this->oidc->clock->sleep(60);
        $this->oidc->provider->answers[TestProvider::DISCOVERY] = static fn (): MockResponse => new MockResponse('', [
            'http_code' => 404,
        ]);
        self::assertSame(OidcFailureType::DiscoveryInvalid, $this->load()->type);
    }

    public function test_a_missing_method_list_supports_no_configured_method(): void
    {
        unset($this->oidc->provider->discovery['token_endpoint_auth_methods_supported']);

        $provider = $this->oidc->configuration()->provider;
        $metadata = $this->oidc->metadata()->load($provider->oidc, $provider->trust);

        self::assertSame([], $metadata->tokenEndpointAuthMethods);
        $client = $provider->oidc->clients['ggd'];
        self::assertSame(ClientAuthentication::None, $client->authentication);
        self::assertFalse($metadata->supports($client->authentication), 'none is not assumed when the list is missing');
    }

    #[DataProvider('failedFetches')]
    public function test_failed_fetches_back_off_without_using_expired_metadata(bool $expired, int $status, OidcFailureType $type): void
    {
        $provider = $this->oidc->configuration()->provider;
        $initialFetches = 0;
        if ($expired) {
            $this->oidc->metadata()->load($provider->oidc, $provider->trust);
            $this->oidc->clock->sleep(3600);
            $initialFetches = 1;
        }
        $this->oidc->provider->answers[TestProvider::DISCOVERY] = static fn (): MockResponse => new MockResponse('', [
            'http_code' => $status,
        ]);

        self::assertSame($type, $this->load()->type);
        self::assertSame($type, $this->load()->type);
        self::assertSame($initialFetches + 1, $this->oidc->provider->countRequests([TestProvider::DISCOVERY]));
        unset($this->oidc->provider->answers[TestProvider::DISCOVERY]);
        $this->oidc->clock->sleep(59);
        self::assertSame($type, $this->load()->type);
        self::assertSame($initialFetches + 1, $this->oidc->provider->countRequests([TestProvider::DISCOVERY]));

        $this->oidc->clock->sleep(1);
        self::assertSame(TestProvider::TOKEN, $this->oidc->metadata()->load($provider->oidc, $provider->trust)->tokenEndpoint);
        self::assertSame($initialFetches + 2, $this->oidc->provider->countRequests([TestProvider::DISCOVERY]));
    }

    /**
     * @return iterable<string, array{bool, int, OidcFailureType}>
     */
    public static function failedFetches(): iterable
    {
        yield 'empty cache, outage' => [false, 503, OidcFailureType::DiscoveryUnavailable];
        yield 'expired cache, outage' => [true, 503, OidcFailureType::DiscoveryUnavailable];
        yield 'empty cache, refusal' => [false, 403, OidcFailureType::DiscoveryInvalid];
        yield 'expired cache, refusal' => [true, 403, OidcFailureType::DiscoveryInvalid];
    }

    private function load(): OidcFailure
    {
        try {
            $provider = $this->oidc->configuration()->provider;
            $this->oidc->metadata()->load($provider->oidc, $provider->trust);
        } catch (OidcFailure $failure) {
            return $failure;
        }

        self::fail('The metadata was accepted.');
    }
}
