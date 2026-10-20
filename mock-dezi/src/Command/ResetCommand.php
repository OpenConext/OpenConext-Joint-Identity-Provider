<?php

declare(strict_types=1);

namespace MockDezi\Command;

use MockDezi\Configuration\ConfigurationLoader;
use MockDezi\Fixture\FixtureRepository;
use MockDezi\Key\KeyRing;
use MockDezi\Store\StateStore;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

#[AsCommand(
    name: 'mock-dezi:reset',
    description: 'Checks the configuration, fixtures and keys, and clears the mock\'s state '
        . '(logins, codes, tokens, used assertion IDs, scenario, endpoint and statement selections)',
)]
final class ResetCommand extends Command
{
    public function __construct(
        private readonly ConfigurationLoader $loader,
        private readonly FixtureRepository $fixtures,
        private readonly KeyRing $keys,
        private readonly StateStore $store,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('check', null, InputOption::VALUE_NONE, 'Only check the configuration, fixtures and keys');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $configuration = $this->loader->load();
            $persons = $this->fixtures->persons();
            $this->keys->assertUsable();
        } catch (Throwable $exception) {
            $output->writeln('<error>' . $exception->getMessage() . '</error>');

            return Command::FAILURE;
        }
        if ($input->getOption('check') === true) {
            $output->writeln(sprintf(
                'Mock DEZI provider %s: configuration, %d client(s), %d person(s) and keys are usable; state kept.',
                $configuration->issuer,
                count($configuration->clients),
                count($persons),
            ));

            return Command::SUCCESS;
        }
        $this->store->reset();
        $output->writeln(sprintf(
            'Mock DEZI provider %s reset: %d client(s), %d person(s), default scenario "success".',
            $configuration->issuer,
            count($configuration->clients),
            count($persons),
        ));

        return Command::SUCCESS;
    }
}
