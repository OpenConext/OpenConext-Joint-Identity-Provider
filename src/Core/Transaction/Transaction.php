<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Transaction;

use DateTimeImmutable;
use InvalidArgumentException;
use JointIdentityProvider\Core\Profile\ProfileResult;
use SensitiveParameter;

/**
 * The transaction record (design §13). The ID is the SBS nonce and a credential; the log ID is the only
 * identifier that may be logged.
 */
final readonly class Transaction
{
    public function __construct(
        #[SensitiveParameter] public string $id,
        public string $logId,
        public string $serviceId,
        public string $organisationId,
        public string $userId,
        public string $connectionPolicyVersionAtStart,
        // The one string value of the binding attribute; empty on a skipped transaction.
        #[SensitiveParameter] public string $organisationBindingValue,
        public string $returnUrl,
        public DateTimeImmutable $transactionDeadline,
        public TransactionState $state,
        public ?ProviderAttempt $attempt = null,
        public ?ProfileResult $profileResult = null,
        public ?DateTimeImmutable $resultDeadline = null,
        public ?string $failureType = null,
        // Whether a new login can succeed after this failure; decides the restart link (design §13).
        public bool $failureRestartable = false,
    ) {
    }

    public function atDezi(ProviderAttempt $attempt): self
    {
        return $this->replace(TransactionState::AtDezi, $attempt, null, false, null, $this->resultDeadline);
    }

    public function validating(): self
    {
        return $this->replace(TransactionState::Validating, $this->attempt, null, false, null, $this->resultDeadline);
    }

    /**
     * The result deadline is the earlier of the transaction deadline and $hardExpiry (design §13).
     */
    public function succeeded(ProfileResult $result, DateTimeImmutable $hardExpiry): self
    {
        return $this->replace(
            TransactionState::Succeeded,
            $this->attempt,
            null,
            false,
            $result,
            min($this->transactionDeadline, $hardExpiry),
        );
    }

    /**
     * A consumed transaction keeps no result: it is never delivered again.
     */
    public function consumed(): self
    {
        return $this->replace(TransactionState::Consumed, $this->attempt, null, false, null, $this->resultDeadline);
    }

    public function failed(string $failureType, bool $restartable): self
    {
        return $this->replace(
            TransactionState::Failed,
            $this->attempt,
            $failureType,
            $restartable,
            null,
            $this->resultDeadline,
        );
    }

    /**
     * The result deadline once set, otherwise the transaction deadline. Past it the transaction counts
     * as expired, whatever its state.
     */
    public function deadline(): DateTimeImmutable
    {
        return $this->resultDeadline ?? $this->transactionDeadline;
    }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->deadline();
    }

    /**
     * Store implementations must run this against the current record inside the atomic replacement.
     * Only the transitions of design §13 are allowed. A result deadline may be assigned once, then only
     * shortened; the start deadline never changes.
     */
    public function assertCanBeReplacedBy(self $replacement): void
    {
        if (
            $replacement->id !== $this->id || $replacement->logId !== $this->logId
            || $replacement->serviceId !== $this->serviceId || $replacement->organisationId !== $this->organisationId
            || $replacement->userId !== $this->userId
            || $replacement->connectionPolicyVersionAtStart !== $this->connectionPolicyVersionAtStart
            || $replacement->organisationBindingValue !== $this->organisationBindingValue
            || $replacement->returnUrl !== $this->returnUrl
            || $replacement->transactionDeadline->format('U.u') !== $this->transactionDeadline->format('U.u')
        ) {
            throw new InvalidArgumentException('A transaction replacement must preserve its start fields.');
        }

        if (!$this->state->canMoveTo($replacement->state)) {
            throw new InvalidArgumentException(sprintf(
                'A transaction cannot move from %s to %s.',
                $this->state->value,
                $replacement->state->value,
            ));
        }

        if (
            ($this->resultDeadline !== null
                && ($replacement->resultDeadline === null || $replacement->resultDeadline > $this->resultDeadline))
            || ($replacement->resultDeadline !== null
                && $replacement->resultDeadline > $this->transactionDeadline)
        ) {
            throw new InvalidArgumentException('A transaction replacement must not extend its deadline.');
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'logId' => $this->logId,
            'serviceId' => $this->serviceId,
            'organisationId' => $this->organisationId,
            'state' => $this->state,
            'deadline' => $this->deadline(),
            'failureType' => $this->failureType,
        ];
    }

    private function replace(
        TransactionState $state,
        ?ProviderAttempt $attempt,
        ?string $failureType,
        bool $failureRestartable,
        ?ProfileResult $profileResult,
        ?DateTimeImmutable $resultDeadline,
    ): self {
        return new self(
            $this->id,
            $this->logId,
            $this->serviceId,
            $this->organisationId,
            $this->userId,
            $this->connectionPolicyVersionAtStart,
            $this->organisationBindingValue,
            $this->returnUrl,
            $this->transactionDeadline,
            $state,
            $attempt,
            $profileResult,
            $resultDeadline,
            $failureType,
            $failureRestartable,
        );
    }
}
