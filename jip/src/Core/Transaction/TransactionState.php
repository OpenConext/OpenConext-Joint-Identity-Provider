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
}
