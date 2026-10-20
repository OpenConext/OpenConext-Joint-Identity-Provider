<?php

declare(strict_types=1);

namespace MockDezi\Tests\Support;

use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

abstract class MockDeziTestCase extends WebTestCase
{
    protected MockDeziFixture $fixture;
    protected KernelBrowser $browser;
    protected JipSimulator $jip;

    protected function setUp(): void
    {
        $this->start(new MockDeziFixture());
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        $this->fixture->remove();
    }

    protected function start(MockDeziFixture $fixture): void
    {
        if (isset($this->fixture)) {
            self::ensureKernelShutdown();
            $this->fixture->remove();
        }
        $this->fixture = $fixture;
        $fixture->apply();
        $this->browser = self::createClient(server: [
            'HTTPS' => 'on',
            'HTTP_HOST' => 'mock-dezi.dev.openconext.local',
        ]);
        $this->jip = new JipSimulator($this->browser, $this->fixture);
    }

    /**
     * @param array<string, mixed> $body
     */
    protected function admin(string $method, string $path, array $body = []): void
    {
        $this->browser->request($method, $path, server: ['CONTENT_TYPE' => 'application/json'], content: json_encode(
            $body,
            JSON_THROW_ON_ERROR,
        ));
    }
}
