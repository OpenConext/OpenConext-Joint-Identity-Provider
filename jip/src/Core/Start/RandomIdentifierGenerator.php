<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Start;

final class RandomIdentifierGenerator implements IdentifierGenerator
{
    public function transactionId(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    public function logId(): string
    {
        return bin2hex(random_bytes(8));
    }
}
