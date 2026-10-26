<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Functional;

use JointIdentityProvider\Tests\Support\ConfigurationFixture;
use JointIdentityProvider\Tests\Support\TestDatabase;
use PDO;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class HealthTest extends WebTestCase
{
    private ConfigurationFixture $fixture;

    protected function setUp(): void
    {
        TestDatabase::reset();
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

    public function test_health_is_up_with_a_valid_configuration(): void
    {
        ConfigurationFixture::setEnv('JIP_CONFIG_FILE', $this->fixture->writeConfiguration($this->fixture->mockConfiguration()));
        $client = self::createClient();

        $client->request('GET', '/health');

        self::assertResponseStatusCodeSame(200);
        self::assertResponseHeaderSame('Strict-Transport-Security', 'max-age=31536000');
        self::assertResponseHeaderSame('Content-Type', 'application/json');
        self::assertResponseHeaderSame('Cache-Control', 'no-store, private');
        self::assertSame('{"status":"UP","certificates":"ok"}', $client->getResponse()->getContent());
    }

    public function test_health_is_down_without_details_when_the_database_is_unavailable(): void
    {
        $configuration = ConfigurationFixture::with(
            $this->fixture->mockConfiguration(),
            ['transactions', 'store', 'password'],
            'wrong-database-secret',
        );
        ConfigurationFixture::setEnv('JIP_CONFIG_FILE', $this->fixture->writeConfiguration($configuration));
        $client = self::createClient();

        $client->request('GET', '/health');

        self::assertResponseStatusCodeSame(503);
        self::assertResponseHeaderSame('Cache-Control', 'no-store, private');
        self::assertSame('{"status":"DOWN"}', $client->getResponse()->getContent());
    }

    public function test_health_is_down_when_the_transaction_table_is_missing(): void
    {
        $configuration = TestDatabase::configuration();
        $db = new PDO($configuration->dsn(), $configuration->user, $configuration->password);
        $db->exec('DROP TABLE jip_transactions');
        ConfigurationFixture::setEnv('JIP_CONFIG_FILE', $this->fixture->writeConfiguration($this->fixture->mockConfiguration()));
        $client = self::createClient();

        $client->request('GET', '/health');

        self::assertResponseStatusCodeSame(503);
        self::assertSame('{"status":"DOWN"}', $client->getResponse()->getContent());
        self::assertFalse(TestDatabase::tableExists());
    }

    public function test_health_is_down_without_details_when_the_configuration_is_invalid(): void
    {
        $configuration = ConfigurationFixture::with(
            $this->fixture->mockConfiguration(),
            ['engineblock', 'api_token'],
            'too-short-secret-value',
        );
        ConfigurationFixture::setEnv('JIP_CONFIG_FILE', $this->fixture->writeConfiguration($configuration));
        $client = self::createClient();

        $client->request('GET', '/health');

        self::assertResponseStatusCodeSame(503);
        self::assertResponseHeaderSame('Strict-Transport-Security', 'max-age=31536000');
        self::assertSame('{"status":"DOWN"}', $client->getResponse()->getContent());
    }

    public function test_health_is_down_when_the_deployment_sets_no_configuration_file(): void
    {
        ConfigurationFixture::setEnv('JIP_CONFIG_FILE', '');
        $client = self::createClient();

        $client->request('GET', '/health');

        self::assertResponseStatusCodeSame(503);
        self::assertResponseHeaderSame('Strict-Transport-Security', 'max-age=31536000');
    }

    public function test_health_accepts_get_only(): void
    {
        ConfigurationFixture::setEnv('JIP_CONFIG_FILE', $this->fixture->writeConfiguration($this->fixture->mockConfiguration()));
        $client = self::createClient();

        $client->request('POST', '/health');

        self::assertResponseStatusCodeSame(405);
        self::assertResponseHeaderSame('Strict-Transport-Security', 'max-age=31536000');
    }
}
