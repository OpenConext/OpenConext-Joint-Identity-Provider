<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Storage;

use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\Transaction\TransactionStore;
use Psr\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Builds the transaction store named by `transactions.store` (design §17).
 */
final readonly class TransactionStoreFactory
{
    public function __construct(
        private ConfigurationLoader $loader,
        private ClockInterface $clock,
        #[Autowire('%kernel.project_dir%')] private string $projectDir,
    ) {
    }

    public function create(): TransactionStore
    {
        $path = $this->loader->load()->transactions->sqlitePath();

        return new SqliteTransactionStore(
            str_starts_with($path, '/') ? $path : $this->projectDir . '/' . $path,
            $this->clock,
        );
    }
}
