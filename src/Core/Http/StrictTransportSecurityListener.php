<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Http;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Covers application responses, including redirects and errors, behind the TLS-terminating proxy.
 */
#[AsEventListener(event: KernelEvents::RESPONSE)]
final readonly class StrictTransportSecurityListener
{
    public function __invoke(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $event->getResponse()->headers->set('Strict-Transport-Security', 'max-age=31536000');
    }
}
