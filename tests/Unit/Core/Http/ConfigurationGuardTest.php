<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Core\Http;

use JointIdentityProvider\Core\Http\ConfigurationGuard;
use JointIdentityProvider\Core\Http\HealthController;
use JointIdentityProvider\Tests\Support\ConfigurationFixture;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

final class ConfigurationGuardTest extends TestCase
{
    private ConfigurationFixture $fixture;

    protected function setUp(): void
    {
        $this->fixture = new ConfigurationFixture();
        ConfigurationFixture::setEnv('EB_API_TOKEN', ConfigurationFixture::API_TOKEN);
    }

    protected function tearDown(): void
    {
        ConfigurationFixture::setEnv('EB_API_TOKEN', null);
        $this->fixture->remove();
    }

    public function test_a_valid_configuration_lets_the_request_through(): void
    {
        $event = $this->dispatch('jip_authz', $this->fixture->mockConfiguration());

        self::assertNull($event->getResponse());
    }

    public function test_an_invalid_configuration_refuses_every_guarded_route(): void
    {
        $event = $this->dispatch('jip_authz', $this->invalidConfiguration());

        self::assertSame(503, $event->getResponse()?->getStatusCode());
        self::assertSame('Service unavailable', $event->getResponse()->getContent());
    }

    public function test_an_unnamed_route_is_guarded_as_well(): void
    {
        $event = $this->dispatch(null, $this->invalidConfiguration());

        self::assertSame(503, $event->getResponse()?->getStatusCode());
    }

    public function test_the_readiness_check_reports_for_itself(): void
    {
        $event = $this->dispatch(HealthController::ROUTE, $this->invalidConfiguration());

        self::assertNull($event->getResponse());
    }

    /**
     * @return array<mixed>
     */
    private function invalidConfiguration(): array
    {
        return ConfigurationFixture::with($this->fixture->mockConfiguration(), ['engineblock', 'api_token'], 'short');
    }

    /**
     * @param array<mixed> $configuration
     */
    private function dispatch(?string $route, array $configuration): RequestEvent
    {
        $request = Request::create('/');
        $request->attributes->set('_route', $route);
        $event = new RequestEvent(
            self::createStub(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
        );

        $guard = new ConfigurationGuard(
            ConfigurationFixture::loader($this->fixture->writeConfiguration($configuration)),
            new NullLogger(),
        );
        $guard($event);

        return $event;
    }
}
