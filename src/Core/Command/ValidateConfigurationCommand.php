<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Command;

use JointIdentityProvider\Core\Configuration\CertificateExpiryCheck;
use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\Configuration\InvalidConfiguration;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'jip:config:validate', description: 'Runs the startup checks on the JIP configuration (design §17).')]
final class ValidateConfigurationCommand extends Command
{
    public function __construct(
        private readonly ConfigurationLoader $loader,
        private readonly CertificateExpiryCheck $certificateExpiry,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        try {
            $configuration = $this->loader->load();
        } catch (InvalidConfiguration $exception) {
            $io->error(sprintf(
                'The JIP configuration is invalid (%d problems). JIP refuses to start.',
                count($exception->errors),
            ));
            $io->listing($exception->errors);

            return Command::FAILURE;
        }

        foreach ($this->certificateExpiry->findings($configuration) as $path => $finding) {
            $io->warning(sprintf('%s: certificate %s', $path, $finding === CertificateExpiryCheck::EXPIRED
                ? 'has expired'
                : sprintf('expires within %d days', $configuration->provider->certificateExpiryWarningDays)));
        }

        $io->success(sprintf(
            'The JIP configuration is valid: environment %s, profile %s, %d client(s), %d service(s).',
            $configuration->environment->value,
            $configuration->provider->profile,
            count($configuration->provider->oidc->clients),
            count($configuration->services),
        ));

        return Command::SUCCESS;
    }
}
