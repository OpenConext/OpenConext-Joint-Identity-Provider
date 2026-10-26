<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Http;

use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\Configuration\InvalidConfiguration;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Every endpoint except the readiness check refuses to serve while the configuration fails a startup
 * check (design §17), independent of the container's health status.
 */
#[AsEventListener(event: KernelEvents::REQUEST, priority: 16)]
final readonly class ConfigurationGuard
{
    public const array UNGUARDED_ROUTES = ['jip_health'];

    public function __construct(
        private ConfigurationLoader $loader,
        private LoggerInterface $logger,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        if (in_array($event->getRequest()->attributes->get('_route'), self::UNGUARDED_ROUTES, true)) {
            return;
        }

        try {
            $this->loader->load();
        } catch (InvalidConfiguration $exception) {
            $this->logger->error(
                'JIP configuration is invalid; refusing the request: {problems}',
                ['problems' => implode('; ', $exception->errors)],
            );
            $event->setResponse(new Response(
                'Service unavailable',
                Response::HTTP_SERVICE_UNAVAILABLE,
                ['Content-Type' => 'text/plain; charset=UTF-8', 'Cache-Control' => 'no-store'],
            ));
        }
    }
}
