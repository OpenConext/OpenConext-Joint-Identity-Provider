<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Transaction;

use DateTimeImmutable;

/**
 * The shared transaction store (design §10, §13). Every state change is one atomic compare-and-set; a
 * read followed by a write or delete does not meet that rule.
 */
interface TransactionStore
{
    /**
     * Stores a new transaction in an initial state (TransactionState::isInitial()). Returns false, and
     * stores nothing, when the ID or the log ID already exists.
     */
    public function add(Transaction $transaction): bool;

    /**
     * A transaction past its deadline may already have been removed; callers treat both as expired.
     */
    public function find(string $transactionId): ?Transaction;

    public function findByOidcState(string $oidcState): ?Transaction;

    /**
     * Atomically replaces the stored transaction with $replacement, only while the stored one is in
     * $expectedState and its deadline lies after both $now and the current time sampled inside the
     * atomic operation at write time, after acquiring any lock. When $validUntil is given, that sampled
     * time must also lie before it. Returns whether the replacement happened.
     * The replacement ID must equal $transactionId. Inside the atomic operation, implementations must
     * call the stored record's assertCanBeReplacedBy($replacement) before writing. An invariant
     * violation throws InvalidArgumentException and leaves the stored record unchanged.
     */
    public function compareAndSet(
        string $transactionId,
        TransactionState $expectedState,
        Transaction $replacement,
        DateTimeImmutable $now,
        ?DateTimeImmutable $validUntil = null,
    ): bool;
}
