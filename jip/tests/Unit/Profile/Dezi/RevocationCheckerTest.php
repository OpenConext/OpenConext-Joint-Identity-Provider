<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Profile\Dezi;

use DateTimeImmutable;
use JointIdentityProvider\Profile\Dezi\DeziFailure;
use JointIdentityProvider\Profile\Dezi\DeziProfileConfiguration;
use JointIdentityProvider\Profile\Dezi\DeziRevocationConfiguration;
use JointIdentityProvider\Profile\Dezi\RevocationChecker;
use JointIdentityProvider\Tests\Support\OidcFixture;
use JointIdentityProvider\Tests\Support\TestProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * The live status check per statement (design §15, §18 "Revocation").
 */
final class RevocationCheckerTest extends TestCase
{
    private OidcFixture $oidc;
    private TestProvider $provider;

    protected function setUp(): void
    {
        $this->oidc = new OidcFixture();
        $this->provider = $this->oidc->provider;
    }

    protected function tearDown(): void
    {
        $this->oidc->remove();
    }

    public function test_an_active_statement_gives_a_decision_valid_from_the_request(): void
    {
        $checkedAt = $this->oidc->clock->now();

        $validUntil = $this->check();

        self::assertEquals($checkedAt->modify('+60 seconds'), $validUntil);
        self::assertSame([$this->provider->statusUrl()], array_column($this->provider->requests, 'url'));
        self::assertEquals(3, $this->provider->requests[0]['options']['timeout'] ?? null);
    }

    public function test_a_configured_timeout_above_five_seconds_reaches_the_http_client(): void
    {
        $configuration = $this->oidc->configuration([
            [['engineblock', 'call_timeout_seconds'], 20],
            [['provider', 'revocation', 'timeout_seconds'], 10],
        ])->provider->profileConfiguration;
        self::assertInstanceOf(DeziProfileConfiguration::class, $configuration);

        new RevocationChecker($this->oidc->http, $this->oidc->clock)->check(
            TestProvider::VERKLARING_ID,
            $configuration->revocation,
        );

        self::assertSame(10.0, $this->provider->requests[0]['options']['timeout'] ?? null);
        self::assertSame(10.0, $this->provider->requests[0]['options']['max_duration'] ?? null);
    }

    public function test_the_url_comes_from_the_configured_template(): void
    {
        $template = TestProvider::ISSUER . '/check/{verklaring_id}/status?v=1';
        $url = TestProvider::ISSUER . '/check/' . TestProvider::VERKLARING_ID . '/status?v=1';
        $this->provider->answers[$url] = static fn (): MockResponse => TestProvider::json([
            'verklaringId' => TestProvider::VERKLARING_ID,
            'status' => 'actief',
        ]);

        $this->check($template);

        self::assertSame([$url], array_column($this->provider->requests, 'url'));
    }

    /**
     * @return iterable<string, array{MockResponse, string, bool}>
     */
    public static function refusals(): iterable
    {
        $other = 'd3e2a1c0-0002-4000-8000-000000000002';
        $id = TestProvider::VERKLARING_ID;

        yield '404' => [TestProvider::json(['type' => 'about:blank'], 404), 'statement_unknown', false];
        yield '400' => [TestProvider::json([], 400), 'status_request_refused', false];
        yield '403' => [TestProvider::json([], 403), 'status_request_refused', false];
        yield '410' => [TestProvider::json([], 410), 'status_request_refused', false];
        yield '500' => [TestProvider::json([], 500), 'status_check_unavailable', true];
        yield '503' => [new MockResponse('', ['http_code' => 503]), 'status_check_unavailable', true];
        yield 'a timeout' => [new MockResponse('', ['error' => 'timeout']), 'status_check_unavailable', true];
        yield 'a redirect' => [new MockResponse('', ['http_code' => 302, 'response_headers' => ['Location' => TestProvider::ISSUER]]), 'status_check_unavailable', true];
        yield '204' => [new MockResponse('', ['http_code' => 204]), 'status_check_unavailable', true];
        yield 'a body that is not JSON' => [new MockResponse('actief'), 'status_check_unavailable', true];
        yield 'a JSON list' => [new MockResponse('["actief"]'), 'status_check_unavailable', true];
        yield 'another statement' => [TestProvider::json(['verklaringId' => $other, 'status' => 'actief']), 'statement_not_active', false];
        yield 'no statement ID' => [TestProvider::json(['status' => 'actief']), 'statement_not_active', false];
        yield 'another status' => [TestProvider::json(['verklaringId' => $id, 'status' => 'ingetrokken']), 'statement_not_active', false];
        yield 'another case' => [TestProvider::json(['verklaringId' => $id, 'status' => 'Actief']), 'statement_not_active', false];
        yield 'no status' => [TestProvider::json(['verklaringId' => $id]), 'statement_not_active', false];
    }

    #[DataProvider('refusals')]
    public function test_only_http_200_with_the_same_id_and_active_status_is_active(
        MockResponse $response,
        string $failureType,
        bool $restartable,
    ): void {
        $this->provider->answers[$this->provider->statusUrl()] = static fn (): MockResponse => $response;

        try {
            $this->check();
            self::fail('The statement was taken as active.');
        } catch (DeziFailure $failure) {
            self::assertSame($failureType, $failure->type->value, $failure->detail);
            self::assertSame($restartable, $failure->type->isRestartable());
        }
        self::assertCount(1, $this->provider->requests);
    }

    private function check(string $template = TestProvider::STATUS_PREFIX . '{verklaring_id}'): DateTimeImmutable
    {
        return new RevocationChecker($this->oidc->http, $this->oidc->clock)->check(
            TestProvider::VERKLARING_ID,
            new DeziRevocationConfiguration(DeziRevocationConfiguration::MODE_STATUS_CHECK, $template, 3, 60),
        );
    }
}
