<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Http;

use JointIdentityProvider\Core\Browser\CallbackController;
use JointIdentityProvider\Core\Browser\InterruptController;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Covers application responses, including redirects and errors, behind the TLS-terminating proxy.
 * Page-specific Content-Security-Policy remains with BrowserPages.
 */
#[AsEventListener(event: KernelEvents::RESPONSE, priority: -256)]
final readonly class ResponseHeadersListener
{
    private const array BROWSER_ROUTES = [InterruptController::ROUTE, CallbackController::ROUTE];

    public function __invoke(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $headers = $event->getResponse()->headers;
        $headers->set('Strict-Transport-Security', 'max-age=31536000');
        $headers->set('Cache-Control', 'no-store');

        if (in_array($event->getRequest()->attributes->get('_route'), self::BROWSER_ROUTES, true)) {
            $headers->set('Referrer-Policy', 'no-referrer');
            $headers->set('X-Frame-Options', 'DENY');
        }
    }
}
