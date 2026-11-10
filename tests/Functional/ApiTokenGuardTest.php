<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Functional;

use JointIdentityProvider\Core\Http\ApiTokenGuard;
use JointIdentityProvider\Tests\Support\ConfigurationFixture as Fixture;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Routing\RouterInterface;

/**
 * Every route requires the API token unless ApiTokenGuard lists it as public.
 */
final class ApiTokenGuardTest extends WebTestCase
{
    private Fixture $fixture;
    private KernelBrowser $client;

    protected function setUp(): void
    {
        $this->fixture = new Fixture();
        Fixture::setEnv('EB_API_TOKEN', Fixture::API_TOKEN);
        Fixture::setEnv('CONNECTOR_ENVIRONMENT', 'mock');
        Fixture::setEnv('JIP_CONFIG_FILE', $this->fixture->writeConfiguration($this->fixture->mockConfiguration()));
        $this->client = self::createClient();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        Fixture::setEnv('EB_API_TOKEN', null);
        Fixture::setEnv('JIP_CONFIG_FILE', null);
        $this->fixture->remove();
    }

    public function test_every_public_route_exists(): void
    {
        $routes = $this->router()->getRouteCollection();
        foreach (ApiTokenGuard::PUBLIC_ROUTES as $name) {
            self::assertNotNull($routes->get($name), $name . ' is not a route');
        }
    }

    public function test_every_other_route_refuses_a_request_without_the_token(): void
    {
        $checked = 0;
        foreach ($this->router()->getRouteCollection()->all() as $name => $route) {
            if (in_array($name, ApiTokenGuard::PUBLIC_ROUTES, true)) {
                continue;
            }

            $path = preg_replace('/\{[^}]+\}/', 'x', $route->getPath()) ?? $route->getPath();
            $this->client->request($route->getMethods()[0] ?? 'GET', $path, server: ['CONTENT_TYPE' => 'application/json'], content: '{}');

            self::assertSame(401, $this->client->getResponse()->getStatusCode(), $name . ' answered without the token');
            $checked++;
        }

        self::assertGreaterThanOrEqual(2, $checked);
    }

    private function router(): RouterInterface
    {
        $router = self::getContainer()->get('router');
        self::assertInstanceOf(RouterInterface::class, $router);

        return $router;
    }
}
