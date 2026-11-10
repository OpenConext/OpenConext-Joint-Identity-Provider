<?php

declare(strict_types=1);

use JointIdentityProvider\Oidc\Http\ProviderHttpClient;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $container): void {
    $container->extension('framework', [
        'http_client' => [
            'scoped_clients' => [
                // Addresses are checked against the approved provider configuration by the callers.
                'jip.provider.client' => ['scope' => '.*', ...ProviderHttpClient::DEFAULT_OPTIONS],
            ],
        ],
    ]);
};
