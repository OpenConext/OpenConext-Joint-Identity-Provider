<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Command;

use JointIdentityProvider\Core\Configuration\InvalidConfiguration;
use JointIdentityProvider\Core\Storage\TransactionStoreFactory;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;

#[AsCommand(name: 'jip:store:init', description: 'Creates the transaction table before serving requests.')]
final class InitializeTransactionStoreCommand extends Command
{
    public function __construct(
        private readonly TransactionStoreFactory $stores,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        try {
            $this->stores->create()->initializeSchema();
        } catch (InvalidConfiguration $exception) {
            $io->error('The JIP configuration is invalid. The transaction store was not initialized.');
            $io->listing($exception->errors);

            return Command::FAILURE;
        } catch (Throwable) {
            // Database exception messages may contain credentials or other received values.
            $io->error('Transaction store initialization failed. Check connectivity, TLS and CREATE privileges.');

            return Command::FAILURE;
        }

        $io->success('The transaction store schema is ready.');

        return Command::SUCCESS;
    }
}
