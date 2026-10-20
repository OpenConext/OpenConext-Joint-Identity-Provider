<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Functional;

use JointIdentityProvider\Tests\Support\ConfigurationFixture;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class ValidateConfigurationCommandTest extends KernelTestCase
{
    private ConfigurationFixture $fixture;

    protected function setUp(): void
    {
        $this->fixture = new ConfigurationFixture();
        ConfigurationFixture::setEnv('EB_API_TOKEN', ConfigurationFixture::API_TOKEN);
        ConfigurationFixture::setEnv('CONNECTOR_ENVIRONMENT', 'mock');
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        ConfigurationFixture::setEnv('EB_API_TOKEN', null);
        ConfigurationFixture::setEnv('JIP_CONFIG_FILE', null);
        $this->fixture->remove();
    }

    public function test_a_valid_configuration_passes(): void
    {
        ConfigurationFixture::setEnv('JIP_CONFIG_FILE', $this->fixture->writeConfiguration($this->fixture->mockConfiguration()));

        $tester = $this->tester();

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertStringContainsString('environment mock, profile dezi', $tester->getDisplay(true));
    }

    public function test_an_invalid_configuration_lists_every_problem_and_fails(): void
    {
        $configuration = ConfigurationFixture::with(
            $this->fixture->mockConfiguration(),
            ['engineblock', 'api_token'],
            'too-short-secret-value',
        );
        $configuration = ConfigurationFixture::with($configuration, ['binding', 'claim'], 'abonnee_nummer');
        ConfigurationFixture::setEnv('JIP_CONFIG_FILE', $this->fixture->writeConfiguration($configuration));

        $tester = $this->tester();

        self::assertSame(Command::FAILURE, $tester->execute([]));
        $display = $tester->getDisplay(true);
        self::assertStringContainsString('engineblock.api_token: must be at least 32 characters', $display);
        self::assertStringContainsString('binding.claim: is not a binding claim that profile dezi allows', $display);
        self::assertStringNotContainsString('too-short-secret-value', $display);
    }

    private function tester(): CommandTester
    {
        $application = new Application(self::bootKernel());

        return new CommandTester($application->find('jip:config:validate'));
    }
}
