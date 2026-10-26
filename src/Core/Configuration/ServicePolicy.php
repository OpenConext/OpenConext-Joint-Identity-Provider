<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

/**
 * The approved policy of one service (design §8, §17 `services`). An empty organisation list denies
 * every organisation.
 */
final readonly class ServicePolicy
{
    /**
     * @param list<string> $allowedOrganisations organisation (IdP) entity IDs
     * @param list<string> $release claim names under attributes.claims
     */
    public function __construct(
        public string $serviceId,
        public string $client,
        public string $connectionPolicyVersion,
        public array $allowedOrganisations,
        public array $release,
        public string $restartLoginUrl,
    ) {
    }
}
