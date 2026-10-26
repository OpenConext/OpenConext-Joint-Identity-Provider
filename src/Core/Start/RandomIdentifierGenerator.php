<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Start;

use JointIdentityProvider\Core\Transaction\TransactionId;

final class RandomIdentifierGenerator implements IdentifierGenerator
{
    public function transactionId(): string
    {
        return TransactionId::generate();
    }

    public function logId(): string
    {
        return bin2hex(random_bytes(8));
    }
}
