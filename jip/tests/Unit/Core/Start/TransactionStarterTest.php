<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Core\Start;

use DateTimeImmutable;
use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Core\Start\IdentifierGenerator;
use JointIdentityProvider\Core\Start\RandomIdentifierGenerator;
use JointIdentityProvider\Core\Start\StartOutcome;
use JointIdentityProvider\Core\Start\StartRequest;
use JointIdentityProvider\Core\Start\TransactionStarter;
use JointIdentityProvider\Core\Storage\SqliteTransactionStore;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Core\Transaction\TransactionStore;
use JointIdentityProvider\Tests\Support\ConfigurationFixture as Fixture;
use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Clock\MockClock;

/**
 * The start decision of design §4 and §13 on the committed mock configuration.
 */
final class TransactionStarterTest extends TestCase
{
    private const string ORGANISATION = 'http://mock-idp';
    private const string BINDING = 'urn:mace:govroam.nl:attribute-def:organisation-dezi-nummer';
    private const string PREFIX = 'urn:mace:govroam.nl:attribute-def:dezi:';
    private const string RETURN_URL = 'https://engine.dev.openconext.local/authentication/idp/process-sraminterrupt';
    private const string NOW = '2026-10-20 12:00:00';

    private Fixture $fixture;
    private JipConfiguration $configuration;
    private MockClock $clock;
    private SqliteTransactionStore $store;

    protected function setUp(): void
    {
        $this->fixture = new Fixture();
        Fixture::setEnv('EB_API_TOKEN', Fixture::API_TOKEN);
        $this->configuration = Fixture::loader($this->fixture->writeConfiguration($this->fixture->mockConfiguration()))->load();
        $this->clock = new MockClock(new DateTimeImmutable(self::NOW));
        $this->store = new SqliteTransactionStore($this->fixture->storePath(), $this->clock);
    }

    protected function tearDown(): void
    {
        Fixture::setEnv('EB_API_TOKEN', null);
        $this->fixture->remove();
    }

    public function test_an_account_with_a_number_opens_a_pending_transaction(): void
    {
        $transaction = $this->created(self::request([self::BINDING => ['123456789'], 'urn:mace:dir:attribute-def:mail' => ['j@example.nl']]));

        self::assertSame(TransactionState::Pending, $transaction->state);
        self::assertSame('123456789', $transaction->organisationBindingValue);
        self::assertSame(Fixture::SERVICE, $transaction->serviceId);
        self::assertSame(self::ORGANISATION, $transaction->organisationId);
        self::assertSame('urn:collab:person:example:jdoe', $transaction->userId);
        self::assertSame('mock-1', $transaction->connectionPolicyVersionAtStart);
        self::assertSame(self::RETURN_URL . '?ID=_abc', $transaction->returnUrl);
        self::assertEquals(new DateTimeImmutable(self::NOW)->modify('+600 seconds'), $transaction->transactionDeadline);
        self::assertNull($transaction->resultDeadline);
        self::assertNull($transaction->failureType);
        self::assertNull($transaction->attempt);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $transaction->id);
        self::assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $transaction->logId);
        self::assertNotSame($transaction->id, $transaction->logId);
        self::assertEquals($transaction, $this->store->find($transaction->id));
    }

    /**
     * @param array<string, mixed> $attributes
     */
    #[DataProvider('accountsWithoutNumber')]
    public function test_an_account_without_a_number_is_skipped(array $attributes): void
    {
        $transaction = $this->created(self::request($attributes));

        self::assertSame(TransactionState::Skipped, $transaction->state);
        self::assertSame('', $transaction->organisationBindingValue);
        self::assertNull($transaction->failureType);
        self::assertEquals($transaction->transactionDeadline, $transaction->resultDeadline);
        self::assertSame(TransactionState::Skipped, $this->store->find($transaction->id)?->state);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function accountsWithoutNumber(): iterable
    {
        yield 'absent' => [['urn:mace:dir:attribute-def:mail' => ['j@example.nl']]];
        yield 'no attributes at all' => [[]];
        yield 'an empty list' => [[self::BINDING => []]];
        yield 'one empty string' => [[self::BINDING => ['']]];
    }

    /**
     * @param array<string, mixed> $attributes
     */
    #[DataProvider('failures')]
    public function test_failed_checks_open_a_failed_transaction(string $organisation, array $attributes, string $failureType): void
    {
        $transaction = $this->created(self::request($attributes, organisation: $organisation));

        self::assertSame(TransactionState::Failed, $transaction->state);
        self::assertSame($failureType, $transaction->failureType);
        self::assertSame('', $transaction->organisationBindingValue);
        self::assertNull($transaction->resultDeadline);
        self::assertSame($failureType, $this->store->find($transaction->id)?->failureType);
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>, string}>
     */
    public static function failures(): iterable
    {
        $refused = 'http://mock-idp2';
        $reserved = [self::PREFIX . 'abonnee-nummer' => ['untrusted-value']];

        yield 'organisation not allowed, with a number' => [$refused, [self::BINDING => ['123456789']], 'organisation_refused'];
        yield 'organisation not allowed, without a number' => [$refused, [], 'organisation_refused'];
        yield 'organisation checked before reserved names and binding' => [$refused, $reserved + [self::BINDING => ['1', '2']], 'organisation_refused'];
        yield 'organisation compared exactly' => ['http://mock-idp/', [], 'organisation_refused'];
        yield 'reserved name with a number' => [self::ORGANISATION, $reserved + [self::BINDING => ['123456789']], 'reserved_attribute'];
        yield 'reserved name without a number' => [self::ORGANISATION, $reserved, 'reserved_attribute'];
        yield 'reserved name checked before binding' => [self::ORGANISATION, $reserved + [self::BINDING => ['1', '2']], 'reserved_attribute'];
        yield 'a forged login flag without a number' => [self::ORGANISATION, [self::PREFIX . 'login' => ['verified']], 'reserved_attribute'];
        yield 'an empty value under a reserved name' => [self::ORGANISATION, [self::PREFIX . 'rol-code' => []], 'reserved_attribute'];
        yield 'an unmapped name in the reserved namespace' => [self::ORGANISATION, [self::PREFIX . 'anything' => ['x']], 'reserved_attribute'];
        yield 'several numbers' => [self::ORGANISATION, [self::BINDING => ['123456789', '987654321']], 'malformed_binding'];
        yield 'a number of only spaces' => [self::ORGANISATION, [self::BINDING => ['   ']], 'malformed_binding'];
        yield 'an integer number' => [self::ORGANISATION, [self::BINDING => [123456789]], 'malformed_binding'];
    }

    public function test_an_empty_organisation_list_refuses_every_organisation(): void
    {
        $configuration = Fixture::with($this->fixture->mockConfiguration(), ['services', Fixture::SERVICE, 'allowed_organisations'], []);
        $this->configuration = Fixture::loader($this->fixture->writeConfiguration($configuration))->load();

        $transaction = $this->created(self::request([]));

        self::assertSame('organisation_refused', $transaction->failureType);
    }

    public function test_an_unknown_service_is_an_error_and_stores_nothing(): void
    {
        $outcome = $this->starter()->start(self::request([self::BINDING => ['1']], service: 'https://unknown.example/metadata'), $this->configuration);

        self::assertNull($outcome->transaction);
        self::assertSame(StartOutcome::UNKNOWN_SERVICE, $outcome->error);
        self::assertSame(0, $this->storedCount());
    }

    #[DataProvider('invalidReturnUrls')]
    public function test_a_return_url_outside_engineblock_is_an_error(string $returnUrl): void
    {
        $outcome = $this->starter()->start(self::request([], returnUrl: $returnUrl), $this->configuration);

        self::assertSame(StartOutcome::INVALID_RETURN_URL, $outcome->error);
        self::assertSame(0, $this->storedCount());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidReturnUrls(): iterable
    {
        yield 'another host' => ['https://evil.example/authentication/idp/process-sraminterrupt?ID=_abc'];
        yield 'http' => ['http://engine.dev.openconext.local/authentication/idp/process-sraminterrupt?ID=_abc'];
        yield 'host extended' => ['https://engine.dev.openconext.local.evil.example/authentication/idp/process-sraminterrupt'];
        yield 'path extended' => [self::RETURN_URL . 'X?ID=_abc'];
        yield 'sub path' => [self::RETURN_URL . '/../../evil'];
        yield 'fragment' => [self::RETURN_URL . '?ID=_abc#x'];
        yield 'whitespace' => [self::RETURN_URL . '?ID=_abc def'];
        yield 'line break' => [self::RETURN_URL . "?ID=_abc\r\nSet-Cookie: x=y"];
        yield 'credentials before the host' => ['https://engine.dev.openconext.local@evil.example/authentication/idp/process-sraminterrupt'];
    }

    public function test_the_return_url_may_equal_the_prefix(): void
    {
        self::assertSame(self::RETURN_URL, $this->created(self::request([], returnUrl: self::RETURN_URL))->returnUrl);
    }

    /**
     * @param list<string> $transactionIds
     */
    #[DataProvider('unusableNonces')]
    public function test_an_unusable_nonce_is_an_error_never_an_interrupt(array $transactionIds): void
    {
        $outcome = $this->starter(self::identifiers($transactionIds))->start(self::request([]), $this->configuration);

        self::assertNull($outcome->transaction);
        self::assertSame(StartOutcome::NOT_CREATED, $outcome->error);
        self::assertSame(0, $this->storedCount());
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function unusableNonces(): iterable
    {
        yield 'empty' => [['']];
        yield 'too short' => [['abc']];
        yield 'not URL-safe' => [[str_repeat('+', 43)]];
    }

    public function test_a_colliding_transaction_id_is_replaced_by_a_new_one(): void
    {
        $first = str_repeat('a', 43);
        $second = str_repeat('b', 43);
        $this->created(self::request([]), self::identifiers([$first]));

        $transaction = $this->created(self::request([]), self::identifiers([$first, $second]));

        self::assertSame($second, $transaction->id);
    }

    public function test_repeated_collisions_are_an_error(): void
    {
        $id = str_repeat('a', 43);
        $this->created(self::request([]), self::identifiers([$id]));

        $outcome = $this->starter(self::identifiers([$id, $id, $id]))->start(self::request([]), $this->configuration);

        self::assertSame(StartOutcome::NOT_CREATED, $outcome->error);
    }

    public function test_a_store_failure_is_an_error(): void
    {
        file_put_contents($this->fixture->directory . '/not-a-directory', '');
        $store = new SqliteTransactionStore($this->fixture->directory . '/not-a-directory/transactions.sqlite', $this->clock);

        $outcome = $this->starter(store: $store)->start(self::request([]), $this->configuration);

        self::assertNull($outcome->transaction);
        self::assertSame(StartOutcome::NOT_CREATED, $outcome->error);
    }

    public function test_the_start_request_keeps_only_attribute_names_and_the_binding_value(): void
    {
        $request = self::request([
            self::BINDING => ['123456789'],
            'urn:mace:dir:attribute-def:mail' => ['j@example.nl'],
            'urn:mace:dir:attribute-def:eduPersonPrincipalName' => ['jdoe@example.nl'],
        ]);

        self::assertSame(
            [self::BINDING, 'urn:mace:dir:attribute-def:mail', 'urn:mace:dir:attribute-def:eduPersonPrincipalName'],
            $request->attributeNames,
        );
        $exported = var_export(get_object_vars($request), true);
        self::assertStringNotContainsString('j@example.nl', $exported);
        self::assertStringNotContainsString('jdoe@example.nl', $exported);
    }

    /**
     * @param array<string, mixed> $attributes
     */
    private static function request(
        array $attributes,
        string $organisation = self::ORGANISATION,
        string $service = Fixture::SERVICE,
        string $returnUrl = self::RETURN_URL . '?ID=_abc',
    ): StartRequest {
        $request = StartRequest::fromJson([
            'user_id' => 'urn:collab:person:example:jdoe',
            'eppn' => 'jdoe@example.nl',
            'external_subject_id' => '',
            'email' => ['j@example.nl'],
            'continue_url' => $returnUrl,
            'service_id' => $service,
            'issuer_id' => $organisation,
            'attributes' => $attributes,
        ], self::BINDING);
        self::assertNotNull($request);

        return $request;
    }

    private function created(StartRequest $request, ?IdentifierGenerator $identifiers = null): Transaction
    {
        $outcome = $this->starter($identifiers)->start($request, $this->configuration);
        self::assertNull($outcome->error);
        self::assertNotNull($outcome->transaction);

        return $outcome->transaction;
    }

    private function starter(?IdentifierGenerator $identifiers = null, ?TransactionStore $store = null): TransactionStarter
    {
        return new TransactionStarter(
            $store ?? $this->store,
            $identifiers ?? new RandomIdentifierGenerator(),
            $this->clock,
            new NullLogger(),
        );
    }

    /**
     * @param list<string> $transactionIds
     */
    private static function identifiers(array $transactionIds): IdentifierGenerator
    {
        return new class ($transactionIds) implements IdentifierGenerator {
            /**
             * @param list<string> $transactionIds
             */
            public function __construct(private array $transactionIds)
            {
            }

            public function transactionId(): string
            {
                return array_shift($this->transactionIds) ?? '';
            }

            public function logId(): string
            {
                return bin2hex(random_bytes(8));
            }
        };
    }

    private function storedCount(): int
    {
        if (!is_file($this->fixture->storePath())) {
            return 0;
        }

        $statement = new PDO('sqlite:' . $this->fixture->storePath())->query('SELECT COUNT(*) FROM jip_transactions');
        $count = $statement === false ? false : $statement->fetchColumn();

        return is_numeric($count) ? (int) $count : -1;
    }
}
