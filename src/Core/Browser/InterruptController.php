<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Browser;

use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\Login\HandOff;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final readonly class InterruptController
{
    public function __construct(
        private ConfigurationLoader $loader,
        private HandOff $handOff,
        private BrowserResponder $responder,
    ) {
    }

    #[Route('/interrupt', name: 'jip_interrupt', methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $configuration = $this->loader->load();
        $nonce = $request->query->all()['nonce'] ?? null;

        return $this->responder->respond($this->handOff->start(
            is_string($nonce) ? $nonce : null,
            $configuration,
        ));
    }
}
