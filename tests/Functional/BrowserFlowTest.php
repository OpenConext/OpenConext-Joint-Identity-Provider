<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Functional;

use DateTimeImmutable;
use JointIdentityProvider\Core\Logging\LineLogger;
use JointIdentityProvider\Core\Profile\ProfileRegistry;
use JointIdentityProvider\Core\Profile\ProviderProfile;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Core\Transaction\TransactionStore;
use JointIdentityProvider\Oidc\Cache\ProviderCache;
use JointIdentityProvider\Tests\Support\ConfigurationFixture as Fixture;
use JointIdentityProvider\Tests\Support\TestDatabase;
use JointIdentityProvider\Tests\Support\TestProvider;
use JointIdentityProvider\Tests\Support\VerifyingProfile;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Stringable;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\Clock\Test\ClockSensitiveTrait;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\Store\InMemoryStore;

/**
 * GET /interrupt and the standard OIDC part of GET /oidc/callback (design §3, §13, §14), with a fake
 * provider behind JIP's HTTP client.
 */
final class BrowserFlowTest extends WebTestCase
{
    use ClockSensitiveTrait;

    private const string JIP = 'https://jip.dev.openconext.local';
    private const string BINDING = 'urn:mace:govroam.nl:attribute-def:organisation-dezi-nummer';
    private const string RETURN_URL = 'https://engine.dev.openconext.local/authentication/idp/process-sraminterrupt?ID=_8f3c';
    private const string RESTART_URL = 'https://jip-test-sp.dev.openconext.local/';

    private Fixture $fixture;
    private KernelBrowser $client;
    private TestProvider $provider;
    /** @var list<string> */
    private array $logLines = [];

    protected function setUp(): void
    {
        TestDatabase::reset();
        $this->fixture = new Fixture();
        Fixture::setEnv('EB_API_TOKEN', Fixture::API_TOKEN);
        Fixture::setEnv('CONNECTOR_ENVIRONMENT', 'mock');
        Fixture::setEnv('JIP_CONFIG_FILE', $this->fixture->writeConfiguration($this->fixture->mockConfiguration()));
        $this->client = self::createClient();
        $this->client->disableReboot();

        $cache = self::getContainer()->get('cache.jip_provider');
        self::assertInstanceOf(CacheItemPoolInterface::class, $cache);
        self::assertTrue($cache->clear());

        $provider = self::getContainer()->get(TestProvider::class);
        self::assertInstanceOf(TestProvider::class, $provider);
        $this->provider = $provider;
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        Fixture::setEnv('EB_API_TOKEN', null);
        Fixture::setEnv('JIP_CONFIG_FILE', null);
        $this->fixture->remove();
    }

    public function test_a_pending_transaction_is_sent_to_the_provider_for_a_fresh_login(): void
    {
        $id = $this->start(['900000001']);

        $query = $this->handOff($id);

        $response = $this->client->getResponse();
        self::assertSame(302, $response->getStatusCode());
        self::assertResponseHeaderSame('Strict-Transport-Security', 'max-age=31536000');
        self::assertStringStartsWith(TestProvider::AUTHORIZE . '?', (string) $response->headers->get('Location'));
        self::assertSame('no-referrer', $response->headers->get('Referrer-Policy'));
        self::assertSame('DENY', $response->headers->get('X-Frame-Options'));
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        self::assertSame('code', $query['response_type']);
        self::assertSame(TestProvider::CLIENT_ID, $query['client_id']);
        self::assertSame(self::JIP . '/oidc/callback', $query['redirect_uri']);
        self::assertSame('openid', $query['scope']);
        self::assertSame('login', $query['prompt']);
        self::assertSame('0', $query['max_age']);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $query['state']);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $query['nonce']);
        self::assertNotSame($query['state'], $query['nonce']);

        $transaction = $this->stored($id);
        self::assertSame(TransactionState::AtProvider, $transaction->state);
        $attempt = $transaction->attempt;
        self::assertNotNull($attempt);
        self::assertSame($query['state'], $attempt->oidcState);
        self::assertSame($query['nonce'], $attempt->oidcNonce);
        self::assertSame(
            TestProvider::b64(hash('sha256', $attempt->pkceVerifier, true)),
            $query['code_challenge'],
        );
        self::assertNotSame($id, $attempt->oidcState);
    }

    public function test_the_hand_off_sets_the_transactions_own_cookie(): void
    {
        $id = $this->start(['900000001']);
        $this->handOff($id);

        $transaction = $this->stored($id);
        $setCookie = (string) $this->client->getResponse()->headers->get('Set-Cookie');
        self::assertStringStartsWith('__Secure-jip_tx_' . $transaction->logId . '=', $setCookie);
        self::assertStringContainsString('path=/oidc/callback', $setCookie);
        self::assertStringContainsString('secure', $setCookie);
        self::assertStringContainsString('httponly', $setCookie);
        self::assertStringContainsString('samesite=lax', $setCookie);
        self::assertSame(
            $transaction->transactionDeadline->getTimestamp(),
            $this->client->getResponse()->headers->getCookies()[0]->getExpiresTime(),
        );
        self::assertSame($transaction->attempt?->cookieValue, $this->cookie($transaction));
    }

    public function test_a_repeated_hand_off_shows_progress_and_keeps_the_attempt(): void
    {
        $id = $this->start(['900000001']);
        $this->handOff($id);
        $attempt = $this->stored($id)->attempt;

        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);

        self::assertResponseStatusCodeSame(200);
        self::assertSame('Login in progress', $this->client->getCrawler()->filterXPath('//h1')->text());
        self::assertEquals($attempt, $this->stored($id)->attempt);
        self::assertSame(1, $this->provider->countRequests([TestProvider::DISCOVERY]));
    }

    public function test_a_skipped_transaction_goes_straight_back_to_engineblock(): void
    {
        $id = $this->start([]);

        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);

        self::assertResponseRedirects(self::RETURN_URL, 302);
        self::assertFalse($this->client->getResponse()->headers->has('Set-Cookie'));
        self::assertSame([], $this->provider->requests);
        self::assertSame(TransactionState::Skipped, $this->stored($id)->state);
    }

    public function test_a_failed_start_shows_its_final_failure_without_a_restart_link(): void
    {
        $id = $this->start(['900000001'], 'http://mock-idp2');

        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);

        self::assertResponseStatusCodeSame(403);
        self::assertStringContainsString('JointIdentityProvider (JIP)', $this->bodyText());
        self::assertStringContainsString('organisation_refused', $this->bodyText());
        self::assertStringContainsString($this->stored($id)->logId, $this->bodyText());
        self::assertSame([], $this->links());
        self::assertSame([], $this->provider->requests);
    }

    public function test_an_unknown_or_malformed_nonce_shows_an_error_page(): void
    {
        foreach (['', 'nonce=short', 'nonce=' . str_repeat('A', 43), 'nonce[]=x'] as $query) {
            $this->client->request('GET', self::JIP . '/interrupt?' . $query);
            self::assertResponseStatusCodeSame(400);
        }
        self::assertSame([], $this->provider->requests);
    }

    public function test_mock_authentication_reaches_the_profile_which_fails_closed(): void
    {
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertResponseStatusCodeSame(403);
        self::assertStringContainsString('userinfo_refused', $this->bodyText());
        $transaction = $this->stored($id);
        self::assertSame(TransactionState::Failed, $transaction->state);
        self::assertSame('userinfo_refused', $transaction->failureType);
        self::assertNull($transaction->profileResult);
        self::assertSame(1, $this->provider->countRequests([TestProvider::TOKEN]));
        $form = $this->provider->lastTokenRequestForm();
        self::assertSame('the-code', $form['code']);
        self::assertSame($transaction->attempt?->pkceVerifier, $form['code_verifier']);
        self::assertArrayHasKey('client_assertion', $form);
        self::assertNull($this->cookie($transaction), 'The callback removes the transaction cookie.');
    }

    public function test_an_old_callback_after_restart_leaves_the_new_transaction_and_cookie_untouched(): void
    {
        $oldId = $this->start(['900000001']);
        $oldQuery = $this->handOff($oldId);
        $this->returnFromProvider(['error' => 'access_denied', 'state' => $oldQuery['state']]);
        $old = $this->stored($oldId);
        $newId = $this->start(['900000001']);
        $this->handOff($newId);
        $new = $this->stored($newId);
        $cookie = $this->cookie($new);
        self::assertNotNull($cookie);

        $this->returnFromProvider(['code' => 'old-code', 'state' => $oldQuery['state']]);

        self::assertEquals($old, $this->stored($oldId));
        self::assertEquals($new, $this->stored($newId));
        self::assertSame($cookie, $this->cookie($new));
        self::assertSame(0, $this->provider->countRequests([TestProvider::TOKEN]));
    }

    public function test_a_hand_off_cache_failure_has_a_log_id_and_secure_error_page(): void
    {
        $this->recordLog();
        $pool = $this->createMock(CacheItemPoolInterface::class);
        $pool->method('getItem')->willThrowException(new RuntimeException('Provider cache unavailable.'));
        self::getContainer()->set(ProviderCache::class, new ProviderCache(
            $pool,
            new LockFactory(new InMemoryStore()),
        ));
        $id = $this->start(['900000001']);

        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);
        self::assertResponseStatusCodeSame(500);
        self::assertStringContainsString('internal_error', $this->bodyText());
        self::assertStringContainsString($this->stored($id)->logId, $this->bodyText());
        self::assertResponseHeaderSame('Cache-Control', 'no-store, private');
        self::assertTrue($this->client->getResponse()->headers->has('Content-Security-Policy'));
        self::assertSame(TransactionState::Pending, $this->stored($id)->state);
        self::assertStringContainsString('RuntimeException', implode("\n", $this->logLines));
    }

    public function test_a_replayed_callback_never_redeems_the_code_again(): void
    {
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);
        $cookie = $this->cookie($this->stored($id));
        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        $this->client->getCookieJar()->set(new Cookie('__Secure-jip_tx_' . $this->stored($id)->logId, (string) $cookie, null, '/oidc/callback', 'jip.dev.openconext.local', true));
        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertResponseStatusCodeSame(403);
        self::assertSame(1, $this->provider->countRequests([TestProvider::TOKEN]));
        self::assertSame('userinfo_refused', $this->stored($id)->failureType);
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function callbackReloads(): iterable
    {
        yield 'cookie cleared by success' => [false];
        yield 'original cookie replayed' => [true];
    }

    #[DataProvider('callbackReloads')]
    public function test_a_callback_reload_after_success_is_only_a_request_rejection(bool $restoreCookie): void
    {
        $this->recordLog();
        self::getContainer()->set(ProfileRegistry::class, new ProfileRegistry([new VerifyingProfile()]));
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);
        $original = $this->stored($id);
        $cookie = $this->cookie($original);
        self::assertNotNull($cookie);
        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);
        self::assertResponseStatusCodeSame(302);
        $succeeded = $this->stored($id);
        self::assertSame(TransactionState::Succeeded, $succeeded->state);
        if ($restoreCookie) {
            $this->client->getCookieJar()->set(new Cookie(
                '__Secure-jip_tx_' . $original->logId,
                $cookie,
                null,
                '/oidc/callback',
                'jip.dev.openconext.local',
                true,
            ));
        }

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertResponseStatusCodeSame(400);
        self::assertEquals($succeeded, $this->stored($id));
        self::assertSame(1, $this->provider->countRequests([TestProvider::TOKEN]));
        $this->assertCallbackRejections($succeeded, 1);
    }

    private function assertCallbackRejections(Transaction $transaction, int $count): void
    {
        $warnings = array_values(array_filter(
            $this->logLines,
            static fn (string $line): bool => str_starts_with($line, 'jip.WARNING:'),
        ));
        $expected = 'jip.WARNING: JIP callback ' . $transaction->logId
            . ': refused (callback_mismatch); transaction unchanged (' . $transaction->state->value . ')'
            . ' for service ' . Fixture::SERVICE . ', organisation http://mock-idp, policy version mock-1 at start,'
            . ' EngineBlock request _8f3c';
        self::assertSame(array_fill(0, $count, $expected), $warnings);
    }

    public function test_a_cancel_at_the_provider_fails_the_transaction_with_a_restart_link(): void
    {
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);

        $this->returnFromProvider(['error' => 'access_denied', 'state' => $query['state']]);

        self::assertResponseStatusCodeSame(403);
        self::assertStringContainsString('provider_cancelled', $this->bodyText());
        self::assertSame([self::RESTART_URL], $this->links());
        $transaction = $this->stored($id);
        self::assertSame(TransactionState::Failed, $transaction->state);
        self::assertSame('provider_cancelled', $transaction->failureType);
        self::assertTrue($transaction->failureRestartable);
        self::assertSame(0, $this->provider->countRequests([TestProvider::TOKEN]));

        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);
        self::assertSame([self::RESTART_URL], $this->links());
    }

    public function test_a_provider_error_is_restartable(): void
    {
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);

        $this->returnFromProvider(['error' => 'server_error', 'state' => $query['state'], 'code' => 'ignored']);

        self::assertSame('provider_error', $this->stored($id)->failureType);
        self::assertTrue($this->stored($id)->failureRestartable);
        self::assertSame([self::RESTART_URL], $this->links());
        self::assertSame(0, $this->provider->countRequests([TestProvider::TOKEN]));
    }

    public function test_an_unknown_state_changes_no_transaction(): void
    {
        $id = $this->start(['900000001']);
        $this->handOff($id);

        $this->returnFromProvider(['code' => 'the-code', 'state' => str_repeat('B', 43)]);
        self::assertResponseStatusCodeSame(400);
        $this->returnFromProvider(['code' => 'the-code']);
        self::assertResponseStatusCodeSame(400);

        self::assertSame(TransactionState::AtProvider, $this->stored($id)->state);
        self::assertSame(0, $this->provider->countRequests([TestProvider::TOKEN]));
    }

    public function test_a_missing_or_wrong_cookie_changes_no_transaction(): void
    {
        $this->recordLog();
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);
        $transaction = $this->stored($id);
        $jar = $this->client->getCookieJar();

        $jar->set(new Cookie('__Secure-jip_tx_' . $transaction->logId, 'wrong', null, '/oidc/callback', 'jip.dev.openconext.local', true));
        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);
        self::assertResponseStatusCodeSame(400);
        self::assertResponseHeaderSame('Strict-Transport-Security', 'max-age=31536000');
        self::assertResponseHeaderSame('Referrer-Policy', 'no-referrer');
        self::assertResponseHeaderSame('X-Frame-Options', 'DENY');
        self::assertStringContainsString('callback_mismatch', $this->bodyText());
        self::assertSame([self::RESTART_URL], $this->links());
        $this->assertCallbackRejections($transaction, 1);

        $jar->clear();
        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);
        self::assertResponseStatusCodeSame(400);

        self::assertSame(TransactionState::AtProvider, $this->stored($id)->state);
        self::assertSame(0, $this->provider->countRequests([TestProvider::TOKEN]));
        $this->assertCallbackRejections($transaction, 2);
    }

    public function test_two_tabs_do_not_interfere(): void
    {
        $first = $this->start(['900000001']);
        $firstQuery = $this->handOff($first);
        $second = $this->start(['900000001']);
        $secondQuery = $this->handOff($second);
        self::assertNotSame($this->stored($first)->logId, $this->stored($second)->logId);

        $this->returnFromProvider(['code' => 'code-2', 'state' => $secondQuery['state']]);

        self::assertSame(TransactionState::Failed, $this->stored($second)->state);
        self::assertSame(TransactionState::AtProvider, $this->stored($first)->state);
        self::assertSame($this->stored($first)->attempt?->cookieValue, $this->cookie($this->stored($first)));

        $this->provider->nonce = $firstQuery['nonce'];
        $this->returnFromProvider(['code' => 'code-1', 'state' => $firstQuery['state']]);
        self::assertSame('userinfo_refused', $this->stored($first)->failureType);
    }

    public function test_the_state_of_one_tab_with_the_cookie_of_another_is_refused(): void
    {
        $first = $this->start(['900000001']);
        $firstQuery = $this->handOff($first);
        $second = $this->start(['900000001']);
        $this->handOff($second);
        $jar = $this->client->getCookieJar();
        $jar->expire('__Secure-jip_tx_' . $this->stored($first)->logId, '/oidc/callback', 'jip.dev.openconext.local');

        $this->returnFromProvider(['code' => 'the-code', 'state' => $firstQuery['state']]);

        self::assertStringContainsString('callback_mismatch', $this->bodyText());
        self::assertSame(TransactionState::AtProvider, $this->stored($first)->state);
        self::assertSame(TransactionState::AtProvider, $this->stored($second)->state);
    }

    public function test_an_invalid_id_token_fails_the_transaction_before_the_profile(): void
    {
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);
        $this->provider->nonce = 'another-nonce';

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertSame('id_token_invalid', $this->stored($id)->failureType);
        self::assertFalse($this->stored($id)->failureRestartable);
        self::assertSame([], $this->links());
    }

    public function test_a_stale_authentication_is_refused(): void
    {
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);
        $this->provider->idTokenClaims = ['auth_time' => time() - 900];

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertSame('id_token_invalid', $this->stored($id)->failureType);
    }

    public function test_a_refused_client_authentication_is_final(): void
    {
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);
        $this->provider->answers[TestProvider::TOKEN] = static fn (): MockResponse => TestProvider::json(
            ['error' => 'invalid_client'],
            401,
        );

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertSame('client_authentication_refused', $this->stored($id)->failureType);
        self::assertSame([], $this->links());
        self::assertSame(1, $this->provider->countRequests([TestProvider::TOKEN]));
    }

    public function test_an_unreachable_token_endpoint_is_restartable(): void
    {
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);
        $this->provider->answers[TestProvider::TOKEN] = static fn (): MockResponse => new MockResponse('', ['http_code' => 503]);

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertSame('token_request_unavailable', $this->stored($id)->failureType);
        self::assertSame([self::RESTART_URL], $this->links());
    }

    public function test_unavailable_discovery_keeps_the_transaction_pending(): void
    {
        $id = $this->start(['900000001']);
        $this->provider->answers[TestProvider::DISCOVERY] = static fn (): MockResponse => new MockResponse('', ['http_code' => 503]);

        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);

        self::assertResponseStatusCodeSame(502);
        self::assertStringContainsString('discovery_unavailable', $this->bodyText());
        self::assertSame([self::RESTART_URL], $this->links());
        self::assertSame(TransactionState::Pending, $this->stored($id)->state);
        self::assertFalse($this->client->getResponse()->headers->has('Set-Cookie'));
    }

    public function test_an_unlisted_authentication_method_stops_before_the_provider(): void
    {
        $id = $this->start(['900000001']);
        $this->provider->discovery['token_endpoint_auth_methods_supported'] = ['none'];

        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);

        self::assertStringContainsString('authentication_method_not_supported', $this->bodyText());
        self::assertSame([], $this->links());
        self::assertSame(TransactionState::Pending, $this->stored($id)->state);
    }

    public function test_an_expired_transaction_shows_a_restart_link_and_does_not_change(): void
    {
        $this->recordLog();
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);
        self::mockTime('+601 seconds');

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertStringContainsString('expired', $this->bodyText());
        self::assertSame([self::RESTART_URL], $this->links());
        self::assertSame(0, $this->provider->countRequests([TestProvider::TOKEN]));
        self::assertSame(TransactionState::AtProvider, $this->stored($id)->state);
        $this->assertExpiredLog('callback', $this->stored($id)->logId, TransactionState::AtProvider);
    }

    public function test_a_verified_profile_outcome_still_needs_the_account_binding(): void
    {
        self::getContainer()->set(ProfileRegistry::class, new ProfileRegistry([new VerifyingProfile()]));
        $id = $this->start(['900000002']);
        $query = $this->handOff($id);

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        $transaction = $this->stored($id);
        self::assertSame(TransactionState::Failed, $transaction->state);
        self::assertSame('binding_mismatch', $transaction->failureType);
        self::assertFalse($transaction->failureRestartable);
        self::assertNull($transaction->profileResult);
        self::assertSame([], $this->links());
    }

    public function test_the_binding_is_an_exact_string_comparison(): void
    {
        self::getContainer()->set(ProfileRegistry::class, new ProfileRegistry([new VerifyingProfile([
            'dezi_nummer' => ['0900000001'],
            'abonnee_nummer' => ['90000001'],
        ])]));
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertSame('binding_mismatch', $this->stored($id)->failureType);
    }

    public function test_a_missing_required_claim_fails_the_transaction(): void
    {
        self::getContainer()->set(ProfileRegistry::class, new ProfileRegistry([new VerifyingProfile([
            'dezi_nummer' => ['900000001'],
        ])]));
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertSame('required_claim_missing', $this->stored($id)->failureType);
        self::assertNull($this->stored($id)->profileResult);
    }

    public function test_a_bound_result_succeeds_and_returns_to_engineblock_with_only_the_request_id(): void
    {
        self::getContainer()->set(ProfileRegistry::class, new ProfileRegistry([new VerifyingProfile([
            'dezi_nummer' => ['900000001'],
            'abonnee_nummer' => ['90000001'],
            'achternaam' => ['Mockarts'],
        ])]));
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertResponseRedirects(self::RETURN_URL, 302);
        $transaction = $this->stored($id);
        self::assertSame(TransactionState::Succeeded, $transaction->state);
        // Only the claims the service releases are kept; achternaam is not on its release list.
        self::assertSame(
            ['dezi_nummer' => ['900000001'], 'abonnee_nummer' => ['90000001']],
            $transaction->profileResult?->verifiedClaims(),
        );
        self::assertNotNull($transaction->resultDeadline);
        self::assertLessThanOrEqual($transaction->transactionDeadline, $transaction->resultDeadline);
        self::assertNull($this->cookie($transaction));
    }

    public function test_an_unexpected_profile_exception_fails_with_a_safe_support_page(): void
    {
        $profile = $this->createMock(ProviderProfile::class);
        $dezi = Fixture::deziProfile();
        $profile->method('name')->willReturn($dezi->name());
        $profile->method('messageTypes')->willReturn($dezi->messageTypes());
        $profile->method('claimNames')->willReturn($dezi->claimNames());
        $profile->method('bindingClaims')->willReturn($dezi->bindingClaims());
        $profile->method('providerKeys')->willReturn($dezi->providerKeys());
        $profile->method('parseConfiguration')->willReturnCallback($dezi->parseConfiguration(...));
        $profile->method('validateLogin')->willThrowException(new RuntimeException('secret-received-profile-value'));
        self::getContainer()->set(ProfileRegistry::class, new ProfileRegistry([$profile]));
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertResponseStatusCodeSame(500);
        $transaction = $this->stored($id);
        self::assertSame(TransactionState::Failed, $transaction->state);
        self::assertSame('internal_error', $transaction->failureType);
        self::assertFalse($transaction->failureRestartable);
        self::assertStringContainsString($transaction->logId, $this->bodyText());
        self::assertStringNotContainsString('secret-received-profile-value', $this->bodyText());
        self::assertSame([], $this->links());
        self::assertNull($this->cookie($transaction));

        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);
        self::assertStringContainsString('internal_error', $this->bodyText());
        self::assertStringNotContainsString('Login in progress', $this->bodyText());
    }

    public function test_an_unexpected_oidc_exception_also_fails_the_claimed_attempt(): void
    {
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);
        $this->provider->answers[TestProvider::TOKEN] = static fn (): MockResponse => throw new RuntimeException(
            'secret-token-response-value',
        );

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertResponseStatusCodeSame(500);
        $transaction = $this->stored($id);
        self::assertSame(TransactionState::Failed, $transaction->state);
        self::assertSame('internal_error', $transaction->failureType);
        self::assertStringContainsString($transaction->logId, $this->bodyText());
        self::assertStringNotContainsString('secret-token-response-value', $this->bodyText());
        self::assertSame([], $this->links());
        self::assertNull($this->cookie($transaction));
    }

    public function test_an_internal_error_has_a_safe_page_even_when_failure_persistence_throws(): void
    {
        $store = TestDatabase::store(new NativeClock());
        $brokenStore = $this->createMock(TransactionStore::class);
        $brokenStore->method('add')->willReturnCallback($store->add(...));
        $brokenStore->method('find')->willReturnCallback($store->find(...));
        $brokenStore->method('findByOidcState')->willReturnCallback($store->findByOidcState(...));
        $brokenStore->method('compareAndSet')->willReturnCallback(static function (
            string $id,
            TransactionState $expected,
            Transaction $replacement,
            DateTimeImmutable $now,
        ) use ($store): bool {
            if ($expected === TransactionState::Validating) {
                throw new RuntimeException('secret-storage-error');
            }

            return $store->compareAndSet($id, $expected, $replacement, $now);
        });
        self::getContainer()->set(TransactionStore::class, $brokenStore);
        $errors = [];
        $logger = $this->createMock(LoggerInterface::class);
        $logger->method('error')->willReturnCallback(static function (string|Stringable $message, array $context) use (&$errors): void {
            $errors[] = ['message' => (string) $message, 'context' => $context];
        });
        self::getContainer()->set('jip.logger', $logger);
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);
        $this->provider->answers[TestProvider::TOKEN] = static fn (): MockResponse => throw new RuntimeException(
            'secret-provider-error',
        );

        $this->returnFromProvider(['code' => 'the-code', 'state' => $query['state']]);

        self::assertResponseStatusCodeSame(500);
        $transaction = $this->stored($id);
        // A broken store cannot persist failed, but must not prevent a safe support page or cookie cleanup.
        self::assertSame(TransactionState::Validating, $transaction->state);
        self::assertStringContainsString('internal_error', $this->bodyText());
        self::assertStringContainsString($transaction->logId, $this->bodyText());
        self::assertStringNotContainsString('secret-', $this->bodyText());
        self::assertSame([], $this->links());
        self::assertNull($this->cookie($transaction));
        self::assertCount(2, $errors);
        foreach ($errors as $error) {
            self::assertSame(['log_id' => $transaction->logId, 'exception_class' => RuntimeException::class], $error['context']);
            self::assertStringNotContainsString('secret-', $error['message']);
        }
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function expiredHandOffs(): iterable
    {
        yield 'pending login' => [['900000001']];
        yield 'skipped login' => [[]];
    }

    /**
     * @param list<string> $binding
     */
    #[DataProvider('expiredHandOffs')]
    public function test_an_expired_hand_off_logs_its_outcome(array $binding): void
    {
        self::mockTime();
        $this->recordLog();
        $id = $this->start($binding);
        $logId = $this->stored($id)->logId;
        Clock::get()->sleep(601);

        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);

        self::assertResponseStatusCodeSame(400);
        self::assertStringContainsString($logId, $this->bodyText());
        self::assertStringContainsString('expired', $this->bodyText());
        $this->assertExpiredLog('hand-off', $logId, $binding === [] ? TransactionState::Skipped : TransactionState::Pending);
    }

    /**
     * @return iterable<string, array{TransactionState, bool}>
     */
    public static function expiredCallbackWrites(): iterable
    {
        yield 'claiming the callback' => [TransactionState::AtProvider, false];
        yield 'recording success' => [TransactionState::Validating, false];
        yield 'recording failure' => [TransactionState::Validating, true];
    }

    #[DataProvider('expiredCallbackWrites')]
    public function test_expiry_during_a_callback_write_logs_the_outcome(TransactionState $expected, bool $cancel): void
    {
        self::mockTime();
        $this->recordLog();
        $this->expireAtWrite($expected);
        self::getContainer()->set(ProfileRegistry::class, new ProfileRegistry([new VerifyingProfile()]));
        $id = $this->start(['900000001']);
        $query = $this->handOff($id);
        $logId = $this->stored($id)->logId;

        $this->returnFromProvider(['state' => $query['state']] + ($cancel
            ? ['error' => 'access_denied']
            : ['code' => 'the-code']));

        self::assertResponseStatusCodeSame(400);
        self::assertStringContainsString($logId, $this->bodyText());
        self::assertStringContainsString('expired', $this->bodyText());
        $this->assertExpiredLog('callback', $logId, $expected);
    }

    public function test_expiry_during_the_hand_off_write_logs_the_outcome(): void
    {
        self::mockTime();
        $this->recordLog();
        $this->expireAtWrite(TransactionState::Pending);
        $id = $this->start(['900000001']);
        $logId = $this->stored($id)->logId;

        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);

        self::assertResponseStatusCodeSame(400);
        self::assertStringContainsString($logId, $this->bodyText());
        self::assertStringContainsString('expired', $this->bodyText());
        $this->assertExpiredLog('hand-off', $logId, TransactionState::Pending);
    }

    private function expireAtWrite(TransactionState $state): void
    {
        $store = TestDatabase::store(Clock::get());
        $delayedStore = $this->createMock(TransactionStore::class);
        $delayedStore->method('add')->willReturnCallback($store->add(...));
        $delayedStore->method('find')->willReturnCallback($store->find(...));
        $delayedStore->method('findByOidcState')->willReturnCallback($store->findByOidcState(...));
        $delayedStore->method('compareAndSet')->willReturnCallback(static function (
            string $id,
            TransactionState $expected,
            Transaction $replacement,
            DateTimeImmutable $now,
            ?DateTimeImmutable $validUntil = null,
        ) use (
            $store,
            $state
): bool {
            if ($expected === $state) {
                Clock::get()->sleep(601);
            }

            return $store->compareAndSet($id, $expected, $replacement, $now, $validUntil);
        });
        self::getContainer()->set(TransactionStore::class, $delayedStore);
    }

    private function recordLog(): void
    {
        self::getContainer()->set('jip.logger', new LineLogger('jip', 'info', function (string $line): void {
            $this->logLines[] = $line;
        }));
    }

    private function assertExpiredLog(string $stage, string $logId, TransactionState $state): void
    {
        $lines = array_values(array_filter(
            $this->logLines,
            static fn (string $line): bool => str_contains($line, ': refused (expired)'),
        ));
        self::assertSame([
            'jip.WARNING: JIP ' . $stage . ' ' . $logId . ': refused (expired); transaction unchanged (' . $state->value . ')'
            . ' for service ' . Fixture::SERVICE
            . ', organisation http://mock-idp, policy version mock-1 at start, EngineBlock request _8f3c',
        ], $lines);
    }

    /**
     * @param list<string>|null $binding
     */
    private function start(?array $binding, string $issuer = 'http://mock-idp'): string
    {
        $this->client->request(
            'POST',
            '/authz',
            server: ['HTTP_AUTHORIZATION' => Fixture::API_TOKEN, 'CONTENT_TYPE' => 'application/json'],
            content: json_encode([
                'user_id' => 'urn:collab:person:ggd.example.nl:jdoe',
                'continue_url' => self::RETURN_URL,
                'service_id' => Fixture::SERVICE,
                'issuer_id' => $issuer,
                'attributes' => $binding === [] ? [] : [self::BINDING => $binding],
            ], JSON_THROW_ON_ERROR),
        );
        $body = json_decode((string) $this->client->getResponse()->getContent(), true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($body);
        self::assertIsString($body['nonce'] ?? null);

        return $body['nonce'];
    }

    /**
     * Runs the hand-off and returns the authorisation request's parameters; the fake provider's next ID
     * token carries the request's nonce.
     *
     * @return array<string, string>
     */
    private function handOff(string $id): array
    {
        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);
        self::assertResponseStatusCodeSame(302);

        parse_str((string) parse_url((string) $this->client->getResponse()->headers->get('Location'), PHP_URL_QUERY), $query);
        $parameters = [];
        foreach ($query as $name => $value) {
            $parameters[(string) $name] = is_string($value) ? $value : '';
        }
        $this->provider->nonce = $parameters['nonce'] ?? '';

        return $parameters;
    }

    private function bodyText(): string
    {
        return $this->client->getCrawler()->filterXPath('//body')->text();
    }

    /**
     * @return list<string>
     */
    private function links(): array
    {
        return array_values(array_map(
            static fn (mixed $href): string => is_string($href) ? $href : '',
            $this->client->getCrawler()->filterXPath('//a')->extract(['href']),
        ));
    }

    /**
     * @param array<string, string> $parameters
     */
    private function returnFromProvider(array $parameters): void
    {
        $this->client->request('GET', self::JIP . '/oidc/callback?' . http_build_query($parameters));
    }

    private function cookie(Transaction $transaction): ?string
    {
        return $this->client->getCookieJar()
            ->get('__Secure-jip_tx_' . $transaction->logId, '/oidc/callback', 'jip.dev.openconext.local')
            ?->getValue();
    }

    private function stored(string $id): Transaction
    {
        $transaction = TestDatabase::store(new NativeClock())->find($id);
        self::assertNotNull($transaction);

        return $transaction;
    }
}
