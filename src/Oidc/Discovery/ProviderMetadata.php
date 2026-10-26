<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Discovery;

use JointIdentityProvider\Oidc\Configuration\ClientAuthentication;

/**
 * Discovery metadata after the checks of design §14: the issuer equals the configured issuer and
 * `jwks_uri` equals the approved ID-token key address.
 */
final readonly class ProviderMetadata
{
    /**
     * @param list<string> $tokenEndpointAuthMethods
     */
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public ?string $userinfoEndpoint,
        public array $tokenEndpointAuthMethods,
    ) {
    }

    public function supports(ClientAuthentication $authentication): bool
    {
        return in_array($authentication->value, $this->tokenEndpointAuthMethods, true);
    }
}
