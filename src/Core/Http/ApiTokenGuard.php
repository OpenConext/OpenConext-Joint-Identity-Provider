<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Http;

use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\EngineBlock\ApiTokenAuthenticator;
use JointIdentityProvider\Core\EngineBlock\AuthzController;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * New endpoints require the raw SBS API token unless explicitly public. Runs after routing and the
 * configuration guard, so invalid configuration still produces the startup gate's 503 response.
 */
#[AsEventListener(event: KernelEvents::REQUEST, priority: 8)]
final readonly class ApiTokenGuard
{
    private const array PUBLIC_ROUTES = ['jip_health', 'jip_interrupt', 'jip_oidc_callback'];

    public function __construct(private ConfigurationLoader $loader)
    {
    }

    public function __invoke(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $route = $request->attributes->get('_route');
        if (in_array($route, self::PUBLIC_ROUTES, true)) {
            return;
        }

        $configuration = $this->loader->load();
        if (ApiTokenAuthenticator::isAuthorized($request, $configuration->engineBlock->apiToken)) {
            return;
        }

        // Preserve each SBS endpoint's existing error contract; future endpoints use the generic body.
        $body = $route === 'jip_sbs_authz'
            ? ['msg' => AuthzController::MSG_ERROR]
            : ['error' => 'unauthorized'];
        $event->setResponse(new JsonResponse(
            $body,
            Response::HTTP_UNAUTHORIZED,
            ['Cache-Control' => 'no-store'],
        ));
    }
}
