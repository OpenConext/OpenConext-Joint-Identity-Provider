<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Oidc;

use JointIdentityProvider\Core\Configuration\ProviderConfiguration;
use JointIdentityProvider\Oidc\OidcFailure;
use JointIdentityProvider\Oidc\OidcFailureType;
use JointIdentityProvider\Tests\Support\OidcFixture;
use JointIdentityProvider\Tests\Support\TestProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Approved key sources, the key cache and the bounded refetch of an unknown `kid` (design §14, §18 "Keys").
 * The mock configuration keeps keys for 3600 s and allows one refetch per 60 s.
 */
final class KeyResolverTest extends TestCase
{
    private OidcFixture $oidc;
    private ProviderConfiguration $provider;

    protected function setUp(): void
    {
        $this->oidc = new OidcFixture();
        $this->provider = $this->oidc->configuration()->provider;
    }

    protected function tearDown(): void
    {
        $this->oidc->remove();
    }

    public function test_keys_come_only_from_the_message_types_approved_address_and_are_kept(): void
    {
        $key = $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);
        $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);

        self::assertSame(TestProvider::publicJwk(TestProvider::KID)['n'], $key->get('n'));
        self::assertSame([TestProvider::ID_TOKEN_JWKS], array_column($this->oidc->provider->requests, 'url'));
        $options = $this->oidc->provider->requests[0]['options'];
        self::assertSame(0, $options['max_redirects']);
        self::assertSame(STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT, $options['crypto_method']);
    }

    public function test_an_unknown_kid_right_after_a_fetch_is_refused_without_a_second_fetch(): void
    {
        $this->assertFailure('unknown', OidcFailureType::UnknownKey);

        self::assertSame(1, $this->fetches());
    }

    public function test_an_unknown_kid_triggers_one_refetch_per_interval(): void
    {
        $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);
        $this->oidc->clock->sleep(61);

        $this->assertFailure('unknown', OidcFailureType::UnknownKey);
        $this->assertFailure('unknown', OidcFailureType::UnknownKey);
        self::assertSame(2, $this->fetches());

        $this->oidc->clock->sleep(61);
        $this->assertFailure('unknown', OidcFailureType::UnknownKey);
        self::assertSame(3, $this->fetches());
    }

    public function test_a_refetch_finds_a_new_key(): void
    {
        $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);
        $this->oidc->clock->sleep(61);
        $this->oidc->provider->answers[TestProvider::ID_TOKEN_JWKS] = static fn (): MockResponse => TestProvider::json([
            'keys' => [TestProvider::publicJwk(TestProvider::KID), TestProvider::publicJwk('rotated', 'rotated')],
        ]);

        $key = $this->oidc->keys()->key($this->provider, 'id_token', 'rotated');

        self::assertSame('rotated', $key->get('kid'));
    }

    public function test_a_failed_refetch_keeps_the_kept_keys_until_their_time_ends(): void
    {
        $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);
        $this->oidc->clock->sleep(61);
        $this->oidc->provider->answers[TestProvider::ID_TOKEN_JWKS] = static fn (): MockResponse => new MockResponse(
            'down',
            ['http_code' => 503],
        );

        $this->assertFailure('unknown', OidcFailureType::KeyFetchUnavailable);
        $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);

        $this->oidc->clock->sleep(3600);
        $this->assertFailure(TestProvider::KID, OidcFailureType::KeyFetchUnavailable);
    }

    public function test_a_failed_refetch_stays_restartable_until_a_new_fetch_can_answer(): void
    {
        $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);
        $this->oidc->clock->sleep(61);
        $this->oidc->provider->answers[TestProvider::ID_TOKEN_JWKS] = static fn (): MockResponse => new MockResponse(
            'down',
            ['http_code' => 503],
        );

        $this->assertFailure('rotated', OidcFailureType::KeyFetchUnavailable);
        $this->assertFailure('rotated', OidcFailureType::KeyFetchUnavailable);
        $this->assertFailure('another-unknown-key', OidcFailureType::KeyFetchUnavailable);
        $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);
        self::assertSame(2, $this->fetches());

        $this->oidc->provider->answers[TestProvider::ID_TOKEN_JWKS] = static fn (): MockResponse => TestProvider::json([
            'keys' => [TestProvider::publicJwk(TestProvider::KID), TestProvider::publicJwk('rotated', 'rotated')],
        ]);
        $this->oidc->clock->sleep(59);
        $this->assertFailure('rotated', OidcFailureType::KeyFetchUnavailable);
        self::assertSame(2, $this->fetches());

        $this->oidc->clock->sleep(1);
        self::assertSame('rotated', $this->oidc->keys()->key($this->provider, 'id_token', 'rotated')->get('kid'));
        self::assertSame(3, $this->fetches());
        $this->assertFailure('another-unknown-key', OidcFailureType::UnknownKey);
        self::assertSame(3, $this->fetches());
    }

    public function test_a_refused_refetch_stays_final_during_the_refetch_interval(): void
    {
        $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);
        $this->oidc->clock->sleep(61);
        $this->oidc->provider->answers[TestProvider::ID_TOKEN_JWKS] = static fn (): MockResponse => new MockResponse(
            '{}',
            ['http_code' => 403],
        );

        $this->assertFailure('rotated', OidcFailureType::KeySetInvalid);
        $this->assertFailure('rotated', OidcFailureType::KeySetInvalid);
        $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);
        self::assertSame(2, $this->fetches());
    }

    public function test_expired_keys_are_fetched_again(): void
    {
        $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);
        $this->oidc->clock->sleep(3600);

        $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);

        self::assertSame(2, $this->fetches());
    }

    public function test_a_redirect_is_not_followed_even_to_another_approved_address(): void
    {
        $this->oidc->provider->answers[TestProvider::ID_TOKEN_JWKS] = static fn (): MockResponse => new MockResponse('', [
            'http_code' => 302,
            'response_headers' => ['Location' => TestProvider::STATEMENT_JWKS],
        ]);

        $this->assertFailure(TestProvider::KID, OidcFailureType::KeyFetchUnavailable);
        self::assertSame(0, $this->oidc->provider->countRequests([TestProvider::STATEMENT_JWKS]));
    }

    public function test_an_invalid_body_is_no_answer_and_a_client_error_is_an_invalid_key_set(): void
    {
        $this->oidc->provider->answers[TestProvider::ID_TOKEN_JWKS] = static fn (): MockResponse => new MockResponse('{');
        $this->assertFailure(TestProvider::KID, OidcFailureType::KeyFetchUnavailable);

        $this->oidc->clock->sleep(60);
        $this->oidc->provider->answers[TestProvider::ID_TOKEN_JWKS] = static fn (): MockResponse => new MockResponse(
            '{}',
            ['http_code' => 404],
        );
        $this->assertFailure(TestProvider::KID, OidcFailureType::KeySetInvalid);
    }

    public function test_a_kid_cached_for_another_message_type_is_not_used(): void
    {
        $this->oidc->provider->answers[TestProvider::STATEMENT_JWKS] = static fn (): MockResponse => TestProvider::json([
            'keys' => [TestProvider::publicJwk('statement-key', 'statement-key')],
        ]);
        $this->oidc->keys()->key($this->provider, 'statement', 'statement-key');

        $this->assertFailure('statement-key', OidcFailureType::UnknownKey);
    }

    public function test_a_duplicate_kid_and_unusable_keys_are_dropped(): void
    {
        $this->oidc->provider->answers[TestProvider::ID_TOKEN_JWKS] = static fn (): MockResponse => TestProvider::json([
            'keys' => [
                TestProvider::publicJwk(TestProvider::KID),
                TestProvider::publicJwk(TestProvider::KID, 'other-key'),
                ['kty' => 'RSA', 'kid' => 'enc', 'use' => 'enc'] + TestProvider::publicJwk('enc'),
                ['kty' => 'EC', 'kid' => 'ec', 'crv' => 'P-256', 'x' => 'AA', 'y' => 'AA'],
            ],
        ]);

        $this->assertFailure(TestProvider::KID, OidcFailureType::UnknownKey);
        $this->assertFailure('enc', OidcFailureType::UnknownKey);
        $this->assertFailure('ec', OidcFailureType::UnknownKey);
    }

    #[DataProvider('failedFetches')]
    public function test_failed_fetches_back_off_without_using_expired_keys(bool $expired, int $status, OidcFailureType $type): void
    {
        $initialFetches = 0;
        if ($expired) {
            $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);
            $this->oidc->clock->sleep(3600);
            $initialFetches = 1;
        }
        $this->oidc->provider->answers[TestProvider::ID_TOKEN_JWKS] = static fn (): MockResponse => new MockResponse('', [
            'http_code' => $status,
        ]);

        $this->assertFailure(TestProvider::KID, $type);
        $this->assertFailure(TestProvider::KID, $type);
        self::assertSame($initialFetches + 1, $this->fetches());
        unset($this->oidc->provider->answers[TestProvider::ID_TOKEN_JWKS]);
        $this->oidc->clock->sleep(59);
        $this->assertFailure(TestProvider::KID, $type);
        self::assertSame($initialFetches + 1, $this->fetches());

        $this->oidc->clock->sleep(1);
        self::assertSame(TestProvider::KID, $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID)->get('kid'));
        self::assertSame($initialFetches + 2, $this->fetches());
        $this->oidc->keys()->key($this->provider, 'id_token', TestProvider::KID);
        self::assertSame($initialFetches + 2, $this->fetches());
    }

    /**
     * @return iterable<string, array{bool, int, OidcFailureType}>
     */
    public static function failedFetches(): iterable
    {
        yield 'empty cache, outage' => [false, 503, OidcFailureType::KeyFetchUnavailable];
        yield 'expired cache, outage' => [true, 503, OidcFailureType::KeyFetchUnavailable];
        yield 'empty cache, refusal' => [false, 403, OidcFailureType::KeySetInvalid];
        yield 'expired cache, refusal' => [true, 403, OidcFailureType::KeySetInvalid];
    }

    private function assertFailure(string $kid, OidcFailureType $type): void
    {
        try {
            $this->oidc->keys()->key($this->provider, 'id_token', $kid);
            self::fail('A key was returned.');
        } catch (OidcFailure $failure) {
            self::assertSame($type, $failure->type, $failure->detail);
        }
    }

    private function fetches(): int
    {
        return $this->oidc->provider->countRequests([TestProvider::ID_TOKEN_JWKS]);
    }
}
