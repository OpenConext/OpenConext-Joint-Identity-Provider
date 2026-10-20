<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

final readonly class TransactionConfiguration
{
    // The proof of concept's single-node store (design §11, §13); a shared store is open in §10.
    public const string SQLITE_PREFIX = 'sqlite:';

    public function __construct(
        public int $lifetimeSeconds,
        public string $store,
    ) {
    }

    /**
     * The database path of the `sqlite:<path>` store; relative to the project directory unless absolute.
     */
    public function sqlitePath(): string
    {
        return substr($this->store, strlen(self::SQLITE_PREFIX));
    }
}
