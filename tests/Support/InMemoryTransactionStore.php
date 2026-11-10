<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Support;

use DateTimeImmutable;
use InvalidArgumentException;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Core\Transaction\TransactionStore;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * The TransactionStore contract without a database, with hooks to lose a race or fail.
 */
final class InMemoryTransactionStore implements TransactionStore
{
    /** @var array<string, Transaction> */
    public array $transactions = [];

    /** Replaces the stored record just before the next compare-and-set, as a concurrent request would. */
    public ?Transaction $concurrentChange = null;

    public ?Throwable $failure = null;

    public function __construct(private readonly ClockInterface $clock)
    {
    }

    public function checkAvailability(): void
    {
        $this->throwFailure();
    }

    public function add(Transaction $transaction): bool
    {
        $this->throwFailure();
        if (isset($this->transactions[$transaction->id])) {
            return false;
        }
        $this->transactions[$transaction->id] = $transaction;

        return true;
    }

    public function find(string $transactionId): ?Transaction
    {
        $this->throwFailure();

        return $this->transactions[$transactionId] ?? null;
    }

    public function findByOidcState(string $oidcState): ?Transaction
    {
        $this->throwFailure();
        foreach ($this->transactions as $transaction) {
            if ($transaction->attempt?->oidcState === $oidcState) {
                return $transaction;
            }
        }

        return null;
    }

    public function compareAndSet(
        string $transactionId,
        TransactionState $expectedState,
        Transaction $replacement,
        DateTimeImmutable $now,
        ?DateTimeImmutable $validUntil = null,
    ): bool {
        $this->throwFailure();
        if ($replacement->id !== $transactionId) {
            throw new InvalidArgumentException('The replacement must carry the same transaction ID.');
        }
        if ($this->concurrentChange !== null) {
            $this->transactions[$transactionId] = $this->concurrentChange;
            $this->concurrentChange = null;
        }

        $current = $this->transactions[$transactionId] ?? null;
        $effectiveNow = max($now, $this->clock->now());
        if (
            $current === null || $current->state !== $expectedState || $current->isExpired($effectiveNow)
            || ($validUntil !== null && $effectiveNow >= $validUntil)
        ) {
            return false;
        }

        $current->assertCanBeReplacedBy($replacement);
        $this->transactions[$transactionId] = $replacement;

        return true;
    }

    private function throwFailure(): void
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }
    }
}
