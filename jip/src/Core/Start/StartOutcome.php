<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Start;

use JointIdentityProvider\Core\Transaction\Transaction;

/**
 * The result of a start call: a stored transaction, or an error for EngineBlock (design §12, §13).
 */
final readonly class StartOutcome
{
    public const string UNKNOWN_SERVICE = 'unknown_service';
    public const string INVALID_RETURN_URL = 'invalid_return_url';
    public const string NOT_CREATED = 'transaction_not_created';

    private function __construct(
        public ?Transaction $transaction,
        public ?string $error,
    ) {
    }

    public static function created(Transaction $transaction): self
    {
        return new self($transaction, null);
    }

    public static function error(string $reason): self
    {
        return new self(null, $reason);
    }
}
