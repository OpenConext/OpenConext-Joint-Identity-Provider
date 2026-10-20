<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Transaction;

/**
 * Transaction states (design §13).
 */
enum TransactionState: string
{
    case Pending = 'pending';
    case Skipped = 'skipped';
    case Failed = 'failed';
    case AtProvider = 'at_provider';
    case Validating = 'validating';
    case Succeeded = 'succeeded';
    case Consumed = 'consumed';

    /**
     * The states `/authz` may open a transaction in.
     */
    public function isInitial(): bool
    {
        return in_array($this, [self::Pending, self::Skipped, self::Failed], true);
    }

    /**
     * The transitions of the state diagram in design §13. Failed and consumed are final.
     */
    public function canMoveTo(self $next): bool
    {
        return in_array($next, match ($this) {
            self::Pending => [self::AtProvider],
            self::AtProvider => [self::Validating],
            self::Validating => [self::Succeeded, self::Failed],
            self::Succeeded, self::Skipped => [self::Consumed, self::Failed],
            self::Failed, self::Consumed => [],
        }, true);
    }
}
