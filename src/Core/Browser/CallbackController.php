<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Browser;

use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\Login\LoginCallback;
use JointIdentityProvider\Oidc\Configuration\ClientConfiguration;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final readonly class CallbackController
{
    public const string ROUTE = 'jip_oidc_callback';

    public function __construct(
        private ConfigurationLoader $loader,
        private LoginCallback $callback,
        private BrowserResponder $responder,
    ) {
    }

    #[Route(ClientConfiguration::CALLBACK_PATH, name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $configuration = $this->loader->load();

        return $this->responder->respond($this->callback->complete(
            $request->query->all(),
            TransactionCookie::values($request->cookies->all()),
            $configuration,
        ));
    }
}
