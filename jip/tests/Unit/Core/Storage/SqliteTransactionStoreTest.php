<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Core\Storage;

use DateTimeImmutable;
use InvalidArgumentException;
use JointIdentityProvider\Core\Storage\SqliteTransactionStore;
use JointIdentityProvider\Core\Transaction\ProviderAttempt;
use JointIdentityProvider\Core\Transaction\StoredProfileResult;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Filesystem\Filesystem;

/**
 * Persistence and atomic state changes of the single-node store (design §13).
 */
final class SqliteTransactionStoreTest extends TestCase
{
    private const string START = '2026-10-20 10:00:00.250000';
    // The state diagram of design §13.
    private const array ALLOWED_TRANSITIONS = [
        'pending' => ['at_provider'],
        'at_provider' => ['validating'],
        'validating' => ['succeeded', 'failed'],
        'succeeded' => ['consumed', 'failed'],
        'skipped' => ['consumed', 'failed'],
        'failed' => [],
        'consumed' => [],
    ];

    private string $directory;
    private MockClock $clock;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/jip-store-' . bin2hex(random_bytes(6));
        $this->clock = new MockClock(new DateTimeImmutable(self::START));
    }

    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->directory);
    }

    public function test_a_transaction_survives_a_new_store_instance_with_every_field(): void
    {
        $transaction = self::transaction('t1', TransactionState::Pending);
        self::assertTrue($this->store()->add($transaction));
        $attempt = new ProviderAttempt('state-1', 'nonce-1', 'verifier-1', 'cookie-1', self::at('+5 seconds'));
        $result = new StoredProfileResult(
            ['dezi_nummer' => ['123456789'], 'rol_code' => ['00.000']],
            self::at('+300 seconds'),
            ['verklaring_id' => 'abc', 'auth_time' => 1_791_367_200, 'decision' => null],
        );
        $now = self::at('+10 seconds');
        $store = $this->store();
        self::assertTrue($store->compareAndSet('t1', TransactionState::Pending, self::with($transaction, TransactionState::AtProvider, attempt: $attempt), $now));
        self::assertTrue($store->compareAndSet('t1', TransactionState::AtProvider, self::with($transaction, TransactionState::Validating, attempt: $attempt), $now));
        self::assertTrue($store->compareAndSet('t1', TransactionState::Validating, self::with(
            $transaction,
            TransactionState::Succeeded,
            attempt: $attempt,
            result: $result,
            resultDeadline: self::at('+300 seconds'),
        ), $now));

        $stored = $this->store()->find('t1');

        self::assertNotNull($stored);
        self::assertSame(TransactionState::Succeeded, $stored->state);
        self::assertSame('log-t1', $stored->logId);
        self::assertSame('https://sp.example/metadata', $stored->serviceId);
        self::assertSame('https://idp.example/metadata', $stored->organisationId);
        self::assertSame('urn:collab:person:example:jdoe', $stored->userId);
        self::assertSame('policy-1', $stored->connectionPolicyVersionAtStart);
        self::assertSame('123456789', $stored->organisationBindingValue);
        self::assertSame('https://engine.example/process?ID=_1', $stored->returnUrl);
        self::assertSame(self::at('+600 seconds')->format('U.u'), $stored->transactionDeadline->format('U.u'));
        self::assertSame(self::at('+300 seconds')->format('U.u'), $stored->resultDeadline?->format('U.u'));
        self::assertSame('state-1', $stored->attempt?->oidcState);
        self::assertSame('nonce-1', $stored->attempt->oidcNonce);
        self::assertSame('verifier-1', $stored->attempt->pkceVerifier);
        self::assertSame('cookie-1', $stored->attempt->cookieValue);
        self::assertSame(self::at('+5 seconds')->format('U.u'), $stored->attempt->startedAt->format('U.u'));
        self::assertSame($result->verifiedClaims(), $stored->profileResult?->verifiedClaims());
        self::assertSame($result->recheckState(), $stored->profileResult->recheckState());
        self::assertSame(self::at('+300 seconds')->format('U.u'), $stored->profileResult->hardExpiry()->format('U.u'));
        self::assertSame('t1', $this->store()->findByOidcState('state-1')?->id);
    }

    public function test_an_unknown_transaction_or_state_is_not_found(): void
    {
        self::assertNull($this->store()->find('missing'));
        self::assertNull($this->store()->findByOidcState('missing'));
    }

    public function test_add_refuses_a_duplicate_transaction_id_or_log_id(): void
    {
        $store = $this->store();
        self::assertTrue($store->add(self::transaction('t1', TransactionState::Pending)));

        self::assertFalse($store->add(self::transaction('t1', TransactionState::Skipped, logId: 'other-log')));
        self::assertFalse($store->add(self::transaction('t2', TransactionState::Pending, logId: 'log-t1')));
        self::assertSame(TransactionState::Pending, $store->find('t1')?->state);
        self::assertNull($store->find('t2'));
    }

    #[DataProvider('nonInitialStates')]
    public function test_add_accepts_initial_states_only(TransactionState $state): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->store()->add(self::transaction('t1', $state));
    }

    /**
     * @return iterable<string, array{TransactionState}>
     */
    public static function nonInitialStates(): iterable
    {
        foreach (TransactionState::cases() as $state) {
            if (!$state->isInitial()) {
                yield $state->value => [$state];
            }
        }
    }

    public function test_compare_and_set_needs_the_expected_state(): void
    {
        $store = $this->store();
        $transaction = self::transaction('t1', TransactionState::Skipped);
        $store->add($transaction);

        self::assertFalse($store->compareAndSet('t1', TransactionState::Succeeded, self::with($transaction, TransactionState::Consumed), self::at('+1 second')));
        self::assertFalse($store->compareAndSet('t2', TransactionState::Skipped, self::with(self::transaction('t2', TransactionState::Skipped), TransactionState::Consumed), self::at('+1 second')));
        self::assertSame(TransactionState::Skipped, $store->find('t1')?->state);
    }

    public function test_a_result_is_consumed_only_once(): void
    {
        $store = $this->store();
        $transaction = self::transaction('t1', TransactionState::Skipped);
        $store->add($transaction);
        $consumed = self::with($transaction, TransactionState::Consumed);

        self::assertTrue($store->compareAndSet('t1', TransactionState::Skipped, $consumed, self::at('+1 second')));
        self::assertFalse($store->compareAndSet('t1', TransactionState::Skipped, $consumed, self::at('+1 second')));
        self::assertSame(TransactionState::Consumed, $store->find('t1')?->state);
    }

    public function test_compare_and_set_refuses_an_expired_transaction(): void
    {
        $store = $this->store();
        $transaction = self::transaction('t1', TransactionState::Pending);
        $store->add($transaction);
        $replacement = self::with($transaction, TransactionState::AtProvider);

        self::assertFalse($store->compareAndSet('t1', TransactionState::Pending, $replacement, self::at('+600 seconds')));
        self::assertTrue($store->compareAndSet('t1', TransactionState::Pending, $replacement, self::at('+600 seconds')->modify('-1 usec')));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function consumptionTimes(): iterable
    {
        yield 'just before expiry' => ['+600 seconds -1 usec', true];
        yield 'exactly at expiry' => ['+600 seconds', false];
        yield 'after expiry' => ['+600 seconds +1 usec', false];
    }

    #[DataProvider('consumptionTimes')]
    public function test_consumption_checks_fresh_store_time_after_cleanup(string $offset, bool $consumed): void
    {
        $callerTime = self::at('+599 seconds');
        $clock = self::createStub(ClockInterface::class);
        // Expiry happens after cleanup, so pruning cannot mask a stale consumption check.
        $clock->method('now')->willReturnOnConsecutiveCalls($callerTime, $callerTime, self::at($offset));
        $store = new SqliteTransactionStore($this->path(), $clock);
        $transaction = self::transaction('t1', TransactionState::Skipped);
        self::assertTrue($store->add($transaction));

        self::assertSame($consumed, $store->compareAndSet(
            't1',
            TransactionState::Skipped,
            self::with($transaction, TransactionState::Consumed),
            $callerTime,
        ));
        self::assertSame($consumed ? TransactionState::Consumed : TransactionState::Skipped, $store->find('t1')?->state);
    }

    /**
     * @return iterable<string, array{TransactionState, TransactionState, bool}>
     */
    public static function transitions(): iterable
    {
        foreach (TransactionState::cases() as $from) {
            foreach (TransactionState::cases() as $to) {
                $allowed = in_array($to->value, self::ALLOWED_TRANSITIONS[$from->value], true);
                yield sprintf('%s to %s', $from->value, $to->value) => [$from, $to, $allowed];
            }
        }
    }

    #[DataProvider('transitions')]
    public function test_only_the_transitions_of_the_state_diagram_are_allowed(
        TransactionState $from,
        TransactionState $to,
        bool $allowed,
    ): void {
        self::assertSame($allowed, $from->canMoveTo($to));
    }

    public function test_an_invalid_transition_throws_and_leaves_the_record_unchanged(): void
    {
        $store = $this->store();
        $transaction = self::transaction('t1', TransactionState::Pending);
        $store->add($transaction);

        try {
            $store->compareAndSet('t1', TransactionState::Pending, self::with($transaction, TransactionState::Consumed), self::at('+1 second'));
            self::fail('A pending transaction must not be consumed.');
        } catch (InvalidArgumentException) {
        }

        self::assertSame(TransactionState::Pending, $store->find('t1')?->state);
        self::assertTrue($store->compareAndSet('t1', TransactionState::Pending, self::with($transaction, TransactionState::AtProvider), self::at('+1 second')));
    }

    public function test_a_replacement_must_keep_the_start_fields_and_must_not_extend_the_deadline(): void
    {
        $store = $this->store();
        $transaction = self::transaction('t1', TransactionState::Skipped);
        $store->add($transaction);
        $now = self::at('+1 second');

        $changedOrganisation = new Transaction(
            't1',
            'log-t1',
            $transaction->serviceId,
            'https://other-idp.example/metadata',
            $transaction->userId,
            $transaction->connectionPolicyVersionAtStart,
            '',
            $transaction->returnUrl,
            $transaction->transactionDeadline,
            TransactionState::Consumed,
            resultDeadline: $transaction->resultDeadline,
        );
        $extended = self::with($transaction, TransactionState::Consumed, resultDeadline: self::at('+601 seconds'));

        foreach ([$changedOrganisation, $extended] as $replacement) {
            try {
                $store->compareAndSet('t1', TransactionState::Skipped, $replacement, $now);
                self::fail('The replacement must be refused.');
            } catch (InvalidArgumentException) {
            }
        }

        self::assertSame(TransactionState::Skipped, $store->find('t1')?->state);
    }

    public function test_the_replacement_must_carry_the_same_id(): void
    {
        $store = $this->store();
        $store->add(self::transaction('t1', TransactionState::Skipped));

        $this->expectException(InvalidArgumentException::class);

        $store->compareAndSet('t1', TransactionState::Skipped, self::transaction('t2', TransactionState::Consumed), self::at('+1 second'));
    }

    public function test_records_past_their_deadline_are_removed_when_a_transaction_is_added(): void
    {
        $store = $this->store();
        $store->add(self::transaction('old', TransactionState::Failed));
        $this->clock->modify('+600 seconds');

        $store->add(self::transaction('new', TransactionState::Pending, start: '+600 seconds'));

        self::assertNull($store->find('old'));
        self::assertNotNull($store->find('new'));
    }

    /**
     * @return iterable<string, array{TransactionState, bool}>
     */
    public static function cleanupTransitions(): iterable
    {
        yield 'successful transition' => [TransactionState::Skipped, true];
        yield 'refused transition' => [TransactionState::Succeeded, false];
    }

    #[DataProvider('cleanupTransitions')]
    public function test_compare_and_set_prunes_expired_records_even_when_refused(
        TransactionState $expectedState,
        bool $consumed,
    ): void {
        $store = $this->store();
        self::assertTrue($store->add(self::transaction('old', TransactionState::Failed)));
        $transaction = self::transaction('live', TransactionState::Skipped, start: '+1 second');
        self::assertTrue($store->add($transaction));
        $this->clock->modify('+600 seconds');
        self::assertNotNull($store->find('old'));

        self::assertSame($consumed, $store->compareAndSet(
            'live',
            $expectedState,
            self::with($transaction, TransactionState::Consumed),
            $this->clock->now(),
        ));

        self::assertNull($this->store()->find('old'));
        self::assertSame($consumed ? TransactionState::Consumed : TransactionState::Skipped, $this->store()->find('live')?->state);
    }

    public function test_an_unusable_location_throws(): void
    {
        (new Filesystem())->dumpFile($this->directory . '/file', '');
        $store = new SqliteTransactionStore($this->directory . '/file/transactions.sqlite', $this->clock);

        $this->expectException(RuntimeException::class);

        $store->add(self::transaction('t1', TransactionState::Pending));
    }

    public function test_concurrent_processes_consume_a_result_exactly_once(): void
    {
        $store = $this->store();
        $store->add(self::transaction('race', TransactionState::Skipped, start: 'now'));

        $workers = [];
        $startAt = microtime(true) + 0.5;
        for ($i = 0; $i < 8; $i++) {
            $process = proc_open(
                [PHP_BINARY, dirname(__DIR__, 3) . '/Support/bin/consume-worker.php', $this->path(), 'race', (string) $startAt],
                [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes,
            );
            self::assertIsResource($process);
            $workers[] = [$process, $pipes];
        }

        $outcomes = [];
        foreach ($workers as [$process, $pipes]) {
            $outcomes[] = trim((string) stream_get_contents($pipes[1])) . trim((string) stream_get_contents($pipes[2]));
            proc_close($process);
        }

        sort($outcomes);
        self::assertSame(['consumed', 'refused', 'refused', 'refused', 'refused', 'refused', 'refused', 'refused'], $outcomes);
        self::assertSame(TransactionState::Consumed, $this->store()->find('race')?->state);
    }

    private function path(): string
    {
        return $this->directory . '/transactions.sqlite';
    }

    private function store(): SqliteTransactionStore
    {
        return new SqliteTransactionStore($this->path(), $this->clock);
    }

    private static function at(string $offset): DateTimeImmutable
    {
        return new DateTimeImmutable(self::START)->modify($offset);
    }

    private static function transaction(
        string $id,
        TransactionState $state,
        ?string $logId = null,
        string $start = '+0 seconds',
    ): Transaction {
        $startTime = $start === 'now' ? new DateTimeImmutable() : self::at($start);
        $deadline = $startTime->modify('+600 seconds');

        return new Transaction(
            $id,
            $logId ?? 'log-' . $id,
            'https://sp.example/metadata',
            'https://idp.example/metadata',
            'urn:collab:person:example:jdoe',
            'policy-1',
            $state === TransactionState::Pending ? '123456789' : '',
            'https://engine.example/process?ID=_1',
            $deadline,
            $state,
            resultDeadline: $state === TransactionState::Skipped ? $deadline : null,
        );
    }

    private static function with(
        Transaction $transaction,
        TransactionState $state,
        ?ProviderAttempt $attempt = null,
        ?StoredProfileResult $result = null,
        ?DateTimeImmutable $resultDeadline = null,
    ): Transaction {
        return new Transaction(
            $transaction->id,
            $transaction->logId,
            $transaction->serviceId,
            $transaction->organisationId,
            $transaction->userId,
            $transaction->connectionPolicyVersionAtStart,
            $transaction->organisationBindingValue,
            $transaction->returnUrl,
            $transaction->transactionDeadline,
            $state,
            $attempt,
            $result,
            $resultDeadline ?? $transaction->resultDeadline,
        );
    }
}
