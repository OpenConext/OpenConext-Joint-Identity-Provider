<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

use SensitiveParameter;

/**
 * The MariaDB database that holds the shared transaction store (design §10, §13).
 */
final readonly class TransactionStoreConfiguration
{
    public function __construct(
        public string $host,
        public int $port,
        public string $database,
        public string $user,
        #[SensitiveParameter] public string $password,
        public ?string $tlsCa = null,
    ) {
    }

    public function dsn(): string
    {
        return sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $this->host, $this->port, $this->database);
    }
}
