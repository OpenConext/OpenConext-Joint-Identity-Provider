<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Storage;

use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use Psr\Clock\ClockInterface;

/**
 * Builds the transaction store named by `transactions.store` (design §17).
 */
final readonly class TransactionStoreFactory
{
    public function __construct(
        private ConfigurationLoader $loader,
        private ClockInterface $clock,
    ) {
    }

    public function create(): MariaDbTransactionStore
    {
        return new MariaDbTransactionStore($this->loader->load()->transactions->store, $this->clock);
    }
}
