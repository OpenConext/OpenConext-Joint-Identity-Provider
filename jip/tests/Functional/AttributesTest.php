<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Functional;

use Closure;
use JointIdentityProvider\Core\Logging\LineLogger;
use JointIdentityProvider\Core\Storage\SqliteTransactionStore;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Tests\Support\ConfigurationFixture as Fixture;
use JointIdentityProvider\Tests\Support\TestProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\Clock\Test\ClockSensitiveTrait;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * POST /attributes after a full login against the fake DEZI provider (design §12, §13, §15, §18 "Skip",
 * "Organisation policy", "Revocation", "Transactions", "Profiles").
 */
final class AttributesTest extends WebTestCase
{
    use ClockSensitiveTrait;

    private const string JIP = 'https://jip.dev.openconext.local';
    private const string BINDING = 'urn:mace:govroam.nl:attribute-def:organisation-dezi-nummer';
    private const string RETURN_URL = 'https://engine.dev.openconext.local/authentication/idp/process-sraminterrupt?ID=_8f3c';
    private const string PREFIX = 'urn:mace:govroam.nl:attribute-def:dezi:';
    private const string ALLOWED_ORGANISATIONS = 'allowed_organisations';

    private Fixture $fixture;
    private KernelBrowser $client;
    private TestProvider $provider;
    /** @var list<string> */
    private array $logLines = [];

    protected function setUp(): void
    {
        self::mockTime();
        $this->fixture = new Fixture();
        Fixture::setEnv('EB_API_TOKEN', Fixture::API_TOKEN);
        Fixture::setEnv('CONNECTOR_ENVIRONMENT', 'mock');
        Fixture::setEnv('JIP_CONFIG_FILE', $this->fixture->writeConfiguration($this->fixture->mockConfiguration()));
        $this->client = self::createClient();
        $this->client->disableReboot();

        $cacheDir = self::getContainer()->getParameter('kernel.cache_dir');
        self::assertIsString($cacheDir);
        (new Filesystem())->remove($cacheDir . '/jip-provider');

        $provider = self::getContainer()->get(TestProvider::class);
        self::assertInstanceOf(TestProvider::class, $provider);
        $this->provider = $provider;
        $this->provider->now = Clock::get()->now()->getTimestamp();
        $certificate = file_get_contents($this->fixture->directory . '/decryption.crt');
        self::assertIsString($certificate);
        $this->provider->userInfoRecipient = $certificate;
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        Fixture::setEnv('EB_API_TOKEN', null);
        Fixture::setEnv('JIP_CONFIG_FILE', null);
        $this->fixture->remove();
    }

    public function test_a_verified_result_is_delivered_once(): void
    {
        $id = $this->complete();

        [$status, $body] = $this->deliver($id);

        self::assertSame(200, $status);
        self::assertResponseHeaderSame('Cache-Control', 'no-store, private');
        self::assertSame(['attributes' => [
            self::PREFIX . 'login' => ['verified'],
            self::PREFIX . 'dezi-nummer' => ['900000001'],
            self::PREFIX . 'abonnee-nummer' => ['90000001'],
            self::PREFIX . 'rol-code' => ['01.000'],
        ]], $body);
        $transaction = $this->stored($id);
        self::assertSame(TransactionState::Consumed, $transaction->state);
        self::assertNull($transaction->profileResult);
        // A fresh decision needs no request at delivery.
        self::assertSame(1, $this->statusRequests());

        self::assertSame([404, ['error' => 'not_found']], $this->deliver($id));
    }

    public function test_the_log_correlates_a_verified_login_without_live_values(): void
    {
        $this->recordLog();
        $id = $this->complete();
        $attempt = $this->stored($id)->attempt;
        self::assertNotNull($attempt);

        self::assertSame(200, $this->deliver($id)[0]);

        self::assertNotSame([], $this->logLines);
        foreach ($this->logLines as $line) {
            self::assertMatchesRegularExpression('/^jip\.[A-Z]+: JIP /', $line);
            foreach (
                [
                    $id,
                    $attempt->oidcState,
                    $attempt->oidcNonce,
                    $attempt->pkceVerifier,
                    $attempt->cookieValue,
                    'the-code',
                    Fixture::API_TOKEN,
                    '900000001',
                    '90000001',
                    'jdoe',
                ] as $secret
            ) {
                self::assertStringNotContainsString($secret, $line);
            }
        }
        self::assertCount(1, $this->logLinesMatching(
            '/^jip\.INFO: JIP start [0-9a-f]{16}: pending .* policy version mock-1, EngineBlock request _8f3c$/',
        ));
        self::assertCount(1, $this->logLinesMatching(
            '/^jip\.INFO: JIP result [0-9a-f]{16}: delivered succeeded .* policy version mock-1 at start and'
            . ' mock-1 at delivery, EngineBlock request _8f3c$/',
        ));
    }

    public function test_a_failed_callback_logs_the_profile_detail_with_correlation(): void
    {
        $this->recordLog();
        $this->provider->status = 'ingetrokken';
        $id = $this->complete();

        $logId = $this->stored($id)->logId;
        self::assertContains(
            'jip.WARNING: JIP callback ' . $logId . ': failed (statement_not_active: dezi profile, status check:'
            . ' statement is not active) for service ' . Fixture::SERVICE . ', organisation http://mock-idp, policy'
            . ' version mock-1 at start, EngineBlock request _8f3c',
            $this->logLines,
        );
    }

    /**
     * @return iterable<string, array{string, list<string>|null}>
     */
    public static function roleCodes(): iterable
    {
        yield 'role code 00.000' => ['00.000', ['00.000']];
        yield 'another role code format' => ['1.015', ['1.015']];
        yield 'no role code' => [TestProvider::ABSENT, null];
    }

    /**
     * @param list<string>|null $released
     */
    #[DataProvider('roleCodes')]
    public function test_the_role_code_is_released_as_dezi_sent_it(string $roleCode, ?array $released): void
    {
        $this->provider->statementClaims = ['rol_code' => $roleCode];
        $id = $this->complete();

        [$status, $body] = $this->deliver($id);

        self::assertSame(200, $status);
        self::assertIsArray($body);
        $attributes = $body['attributes'] ?? null;
        self::assertIsArray($attributes);
        self::assertSame($released, $attributes[self::PREFIX . 'rol-code'] ?? null);
        self::assertSame(['verified'], $attributes[self::PREFIX . 'login'] ?? null);
    }

    public function test_a_skipped_result_holds_only_the_flag_and_is_delivered_once(): void
    {
        $id = $this->start([]);
        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);

        self::assertSame([200, ['attributes' => [self::PREFIX . 'login' => ['skipped']]]], $this->deliver($id));
        self::assertSame([404, ['error' => 'not_found']], $this->deliver($id));
        self::assertSame([], $this->provider->requests);
    }

    public function test_a_skipped_result_needs_no_hand_off(): void
    {
        $id = $this->start([]);

        self::assertSame(200, $this->deliver($id)[0]);
    }

    public function test_the_result_call_is_authenticated_with_the_authorization_header_only(): void
    {
        $id = $this->start([]);

        self::assertSame(401, $this->deliver($id, ['HTTP_AUTHORIZATION' => 'wrong', 'HTTP_AUTHENTICATION' => Fixture::API_TOKEN])[0]);
        self::assertSame(401, $this->deliver($id, ['HTTP_AUTHENTICATION' => Fixture::API_TOKEN])[0]);
        self::assertSame(401, $this->deliver($id, ['HTTP_AUTHORIZATION' => 'Bearer ' . Fixture::API_TOKEN])[0]);
        self::assertSame(TransactionState::Skipped, $this->stored($id)->state);

        self::assertSame(200, $this->deliver($id, ['HTTP_AUTHORIZATION' => Fixture::API_TOKEN])[0]);
    }

    public function test_an_unknown_or_malformed_nonce_is_not_found(): void
    {
        self::assertSame(404, $this->deliver(str_repeat('A', 43))[0]);
        self::assertSame(404, $this->deliver('short')[0]);

        $this->client->request('POST', '/attributes', server: self::server(), content: '{"nonce": 1}');
        self::assertResponseStatusCodeSame(404);
        $this->client->request('POST', '/attributes', server: self::server(), content: 'not json');
        self::assertResponseStatusCodeSame(400);
    }

    public function test_a_result_call_before_completion_is_forbidden_and_changes_nothing(): void
    {
        $id = $this->start(['900000001']);
        self::assertSame([403, ['error' => 'forbidden']], $this->deliver($id));
        self::assertSame(TransactionState::Pending, $this->stored($id)->state);

        $this->handOff($id);
        self::assertSame(403, $this->deliver($id)[0]);
        self::assertSame(TransactionState::AtProvider, $this->stored($id)->state);
    }

    public function test_a_failed_binding_releases_nothing(): void
    {
        $id = $this->complete(['900000002']);
        self::assertSame('binding_mismatch', $this->stored($id)->failureType);

        self::assertSame([403, ['error' => 'forbidden']], $this->deliver($id));
        self::assertSame(TransactionState::Failed, $this->stored($id)->state);
    }

    public function test_a_revoked_statement_releases_nothing(): void
    {
        $this->provider->status = 'ingetrokken';
        $id = $this->complete();
        self::assertSame('statement_not_active', $this->stored($id)->failureType);

        self::assertSame(403, $this->deliver($id)[0]);
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function bindings(): iterable
    {
        yield 'a verified transaction' => [['900000001']];
        yield 'a skipped transaction' => [[]];
    }

    /**
     * @param list<string> $binding
     */
    #[DataProvider('bindings')]
    public function test_an_organisation_withdrawn_after_the_start_releases_nothing(array $binding): void
    {
        $id = $binding === [] ? $this->start([]) : $this->complete($binding);
        $this->reconfigure([[['services', Fixture::SERVICE, self::ALLOWED_ORGANISATIONS], []]]);

        self::assertSame([403, ['error' => 'forbidden']], $this->deliver($id));

        $transaction = $this->stored($id);
        self::assertSame(TransactionState::Failed, $transaction->state);
        self::assertSame('organisation_refused', $transaction->failureType);
        self::assertSame(403, $this->deliver($id)[0]);
    }

    public function test_a_service_removed_after_the_start_releases_nothing(): void
    {
        $id = $this->complete();
        $this->reconfigure([[['services', Fixture::SERVICE], Fixture::ABSENT], [['services', 'https://other-sp.example/metadata'], [
            'client' => 'ggd',
            'connection_policy_version' => 'mock-2',
            self::ALLOWED_ORGANISATIONS => ['http://mock-idp'],
            'restart_login_url' => 'https://other-sp.example/',
        ]]]);

        self::assertSame(403, $this->deliver($id)[0]);
        self::assertSame('service_not_configured', $this->stored($id)->failureType);
    }

    public function test_a_withdrawal_during_the_recheck_is_caught_before_consumption(): void
    {
        $id = $this->complete();
        Clock::get()->sleep(61);
        $this->provider->answers[$this->provider->statusUrl()] = function (): MockResponse {
            $this->reconfigure([[['services', Fixture::SERVICE, self::ALLOWED_ORGANISATIONS], []]]);

            return self::active();
        };

        self::assertSame(403, $this->deliver($id)[0]);
        self::assertSame('organisation_refused', $this->stored($id)->failureType);
    }

    public function test_a_result_with_nothing_left_to_release_is_refused(): void
    {
        $id = $this->complete();
        $this->reconfigure([[['services', Fixture::SERVICE, 'release'], ['rol_naam']]]);

        self::assertSame(403, $this->deliver($id)[0]);
        self::assertSame('nothing_to_release', $this->stored($id)->failureType);
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function decisionAges(): iterable
    {
        yield 'valid for longer than the status timeout' => [54, 1];
        yield 'within the status timeout of its expiry' => [56, 2];
        yield 'aged' => [61, 2];
    }

    #[DataProvider('decisionAges')]
    public function test_an_aged_decision_is_renewed_with_one_request(int $age, int $statusRequests): void
    {
        $id = $this->complete();
        Clock::get()->sleep($age);

        self::assertSame(200, $this->deliver($id)[0]);
        self::assertSame($statusRequests, $this->statusRequests());
    }

    /**
     * @return iterable<string, array{Closure(): MockResponse, string, bool}>
     */
    public static function failedRenewals(): iterable
    {
        yield 'revoked' => [static fn (): MockResponse => TestProvider::json([
            'verklaringId' => TestProvider::VERKLARING_ID,
            'status' => 'ingetrokken',
        ]), 'statement_not_active', false];
        yield 'unknown' => [static fn (): MockResponse => TestProvider::json([], 404), 'statement_unknown', false];
        yield 'no answer' => [static fn (): MockResponse => new MockResponse('', ['http_code' => 503]), 'status_check_unavailable', true];
    }

    /**
     * @param Closure(): MockResponse $answer
     */
    #[DataProvider('failedRenewals')]
    public function test_an_aged_decision_that_cannot_be_renewed_releases_nothing(
        Closure $answer,
        string $failureType,
        bool $restartable,
    ): void {
        $id = $this->complete();
        Clock::get()->sleep(61);
        $this->provider->answers[$this->provider->statusUrl()] = $answer;

        self::assertSame([403, ['error' => 'forbidden']], $this->deliver($id));

        $transaction = $this->stored($id);
        self::assertSame(TransactionState::Failed, $transaction->state);
        self::assertSame($failureType, $transaction->failureType);
        self::assertSame($restartable, $transaction->failureRestartable);
        self::assertSame(2, $this->statusRequests());
        self::assertSame(403, $this->deliver($id)[0]);
        self::assertSame(2, $this->statusRequests());
    }

    public function test_a_decision_that_ends_between_recheck_and_consumption_fails_the_transaction(): void
    {
        $id = $this->complete();
        Clock::get()->sleep(61);
        // The renewed decision holds 60 seconds from the request; this answer arrives later.
        $this->provider->answers[$this->provider->statusUrl()] = static function (): MockResponse {
            Clock::get()->sleep(61);

            return self::active();
        };

        self::assertSame(403, $this->deliver($id)[0]);

        $transaction = $this->stored($id);
        self::assertSame(TransactionState::Failed, $transaction->state);
        self::assertSame('expired', $transaction->failureType);
        self::assertTrue($transaction->failureRestartable);
    }

    public function test_expiry_of_the_proof_during_the_recheck_releases_nothing(): void
    {
        $this->recordLog();
        $id = $this->complete();
        $logId = $this->stored($id)->logId;
        Clock::get()->sleep(61);
        // The envelope expires 300 seconds after it was issued.
        $this->provider->answers[$this->provider->statusUrl()] = static function (): MockResponse {
            Clock::get()->sleep(240);

            return self::active();
        };

        self::assertSame([404, ['error' => 'not_found']], $this->deliver($id));
        self::assertNull($this->storedOrNull($id));
        $this->assertExpiredLog($logId, 'succeeded');
    }

    public function test_a_result_past_its_deadline_is_not_found_without_a_status_check(): void
    {
        $this->recordLog();
        $id = $this->complete();
        $logId = $this->stored($id)->logId;
        Clock::get()->sleep(301);

        self::assertSame([404, ['error' => 'not_found']], $this->deliver($id));
        self::assertSame(1, $this->statusRequests());
        $this->assertExpiredLog($logId, 'succeeded');
    }

    public function test_a_skipped_result_past_the_transaction_deadline_is_not_found(): void
    {
        $this->recordLog();
        $id = $this->start([]);
        $logId = $this->stored($id)->logId;
        Clock::get()->sleep(600);

        self::assertSame(404, $this->deliver($id)[0]);
        $this->assertExpiredLog($logId, 'skipped');
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function consumedReplays(): iterable
    {
        yield 'before the deadline' => [0];
        yield 'after the deadline' => [301];
    }

    #[DataProvider('consumedReplays')]
    public function test_consumed_replays_are_logged_as_reuse_without_a_new_outcome(int $delay): void
    {
        $this->recordLog();
        $id = $this->complete();
        $attempt = $this->stored($id)->attempt;
        self::assertNotNull($attempt);
        self::assertSame(200, $this->deliver($id)[0]);
        $consumed = $this->stored($id);
        $before = count($this->logLines);
        Clock::get()->sleep($delay);

        self::assertSame([404, ['error' => 'not_found']], $this->deliver($id));
        $this->client->request('GET', self::JIP . '/oidc/callback?' . http_build_query([
            'state' => $attempt->oidcState,
            'code' => 'the-code',
        ]));
        self::assertResponseStatusCodeSame(400);
        self::assertStringContainsString('already_used', (string) $this->client->getResponse()->getContent());
        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);
        self::assertResponseStatusCodeSame(400);
        self::assertStringContainsString('already_used', (string) $this->client->getResponse()->getContent());

        self::assertEquals($consumed, $this->stored($id));
        self::assertCount(1, $this->logLinesMatching('/JIP result .*: delivered succeeded /'));
        self::assertSame([], $this->logLinesMatching('/: failed \(/'));
        $rejections = array_slice($this->logLines, $before);
        self::assertCount(3, $rejections);
        foreach ($rejections as $line) {
            self::assertStringContainsString($consumed->logId . ': refused (already_used); transaction unchanged (consumed)', $line);
            self::assertStringContainsString('for service ' . Fixture::SERVICE . ', organisation http://mock-idp', $line);
            self::assertStringContainsString('EngineBlock request _8f3c', $line);
            self::assertStringNotContainsString('expired', $line);
        }
        self::assertSame(1, $this->provider->countRequests([TestProvider::TOKEN]));
        self::assertSame(1, $this->statusRequests());
    }

    private function assertExpiredLog(string $logId, string $state): void
    {
        $lines = $this->logLinesMatching('/JIP result .*: refused \(expired\)/');
        self::assertSame([
            'jip.WARNING: JIP result ' . $logId . ': refused (expired); transaction unchanged (' . $state . ') for service ' . Fixture::SERVICE
            . ', organisation http://mock-idp, policy version mock-1 at start and mock-1 at delivery,'
            . ' EngineBlock request _8f3c',
        ], $lines);
    }

    /**
     * Runs start, hand-off and callback against the fake provider.
     *
     * @param list<string> $binding
     */
    private function complete(array $binding = ['900000001']): string
    {
        $id = $this->start($binding);
        $state = $this->handOff($id);
        $this->client->request('GET', self::JIP . '/oidc/callback?' . http_build_query(['code' => 'the-code', 'state' => $state]));

        return $id;
    }

    /**
     * @param list<string> $binding
     */
    private function start(array $binding): string
    {
        $this->client->request(
            'POST',
            '/authz',
            server: self::server(),
            content: json_encode([
                'user_id' => 'urn:collab:person:ggd.example.nl:jdoe',
                'continue_url' => self::RETURN_URL,
                'service_id' => Fixture::SERVICE,
                'issuer_id' => 'http://mock-idp',
                'attributes' => $binding === [] ? [] : [self::BINDING => $binding],
            ], JSON_THROW_ON_ERROR),
        );
        $body = json_decode((string) $this->client->getResponse()->getContent(), true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($body);
        self::assertIsString($body['nonce'] ?? null);

        return $body['nonce'];
    }

    /**
     * Returns the authorisation request's state; the fake provider's next ID token carries its nonce.
     */
    private function handOff(string $id): string
    {
        $this->client->request('GET', self::JIP . '/interrupt?nonce=' . $id);
        self::assertResponseStatusCodeSame(302);

        parse_str((string) parse_url((string) $this->client->getResponse()->headers->get('Location'), PHP_URL_QUERY), $query);
        $nonce = $query['nonce'] ?? null;
        $state = $query['state'] ?? null;
        self::assertIsString($nonce);
        self::assertIsString($state);
        $this->provider->nonce = $nonce;

        return $state;
    }

    /**
     * @param array<string, string>|null $server
     * @return array{int, mixed}
     */
    private function deliver(string $nonce, ?array $server = null): array
    {
        $this->client->request(
            'POST',
            '/attributes',
            server: $server === null ? self::server() : $server + ['CONTENT_TYPE' => 'application/json'],
            content: json_encode(['nonce' => $nonce], JSON_THROW_ON_ERROR),
        );
        $response = $this->client->getResponse();

        return [$response->getStatusCode(), json_decode((string) $response->getContent(), true, 8, JSON_THROW_ON_ERROR)];
    }

    /**
     * @return array<string, string>
     */
    private static function server(): array
    {
        return ['HTTP_AUTHORIZATION' => Fixture::API_TOKEN, 'CONTENT_TYPE' => 'application/json'];
    }

    private static function active(): MockResponse
    {
        return TestProvider::json(['verklaringId' => TestProvider::VERKLARING_ID, 'status' => 'actief']);
    }

    /**
     * Rewrites the configuration file; the next decision reads it.
     *
     * @param list<array{list<string|int>, mixed}> $changes
     */
    private function reconfigure(array $changes): void
    {
        $data = $this->fixture->mockConfiguration();
        foreach ($changes as [$path, $value]) {
            /** @var array<string, mixed> $data */
            $data = Fixture::with($data, $path, $value);
        }
        $this->fixture->writeConfiguration($data);
    }

    private function statusRequests(): int
    {
        return $this->provider->countRequests([$this->provider->statusUrl()]);
    }

    private function recordLog(): void
    {
        self::getContainer()->set('jip.logger', new LineLogger('jip', 'info', function (string $line): void {
            $this->logLines[] = $line;
        }));
    }

    /**
     * @return list<string>
     */
    private function logLinesMatching(string $pattern): array
    {
        return array_values(array_filter(
            $this->logLines,
            static fn (string $line): bool => preg_match($pattern, $line) === 1,
        ));
    }

    private function stored(string $id): Transaction
    {
        $transaction = $this->storedOrNull($id);
        self::assertNotNull($transaction);

        return $transaction;
    }

    private function storedOrNull(string $id): ?Transaction
    {
        return new SqliteTransactionStore($this->fixture->storePath(), new NativeClock())->find($id);
    }
}
