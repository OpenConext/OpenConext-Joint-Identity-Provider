<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

final readonly class TransactionConfiguration
{
    public function __construct(
        public int $lifetimeSeconds,
        public string $store,
    ) {
    }
}
