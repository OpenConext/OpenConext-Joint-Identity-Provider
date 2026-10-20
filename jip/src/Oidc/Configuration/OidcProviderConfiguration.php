<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Configuration;

/**
 * The standard OIDC client's part of the `provider` block (design §14, §17).
 */
final readonly class OidcProviderConfiguration
{
    /**
     * @param array<string, ClientConfiguration> $clients keyed by the name services refer to
     */
    public function __construct(
        public string $issuer,
        public AuthorizationParameters $authorization,
        public array $clients,
    ) {
    }
}
