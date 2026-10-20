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
     * Stores a new transaction. Returns false, and stores nothing, when the ID already exists.
     */
    public function add(Transaction $transaction): bool;

    public function find(string $transactionId): ?Transaction;

    public function findByOidcState(string $oidcState): ?Transaction;

    /**
     * Atomically replaces the stored transaction with $replacement, only while the stored one is in
     * $expectedState and its deadline lies after $now. Returns whether the replacement happened.
     * The replacement ID must equal $transactionId. Inside the atomic operation, implementations must
     * call the stored record's assertCanBeReplacedBy($replacement) before writing. An invariant
     * violation throws InvalidArgumentException and leaves the stored record unchanged.
     */
    public function compareAndSet(
        string $transactionId,
        TransactionState $expectedState,
        Transaction $replacement,
        DateTimeImmutable $now,
    ): bool;
}
