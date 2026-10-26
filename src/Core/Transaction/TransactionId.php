<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Transaction;

final class TransactionId
{
    public static function generate(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    public static function isValid(string $value): bool
    {
        return preg_match('/^[A-Za-z0-9_-]{43}\z/', $value) === 1;
    }
}
