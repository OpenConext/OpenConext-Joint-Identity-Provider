<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

/**
 * The claim mapping shared by all services (design §17 `attributes`). The core takes every claim and
 * attribute name from here; it knows no provider's claim names itself.
 */
final readonly class AttributeMapping
{
    /**
     * @param array<string, ClaimMapping> $claims keyed by claim name
     */
    public function __construct(
        public string $reservedPrefix,
        public string $loginFlag,
        public array $claims,
    ) {
    }

    /**
     * @return list<string>
     */
    public function defaultReleaseClaims(): array
    {
        $claims = [];
        foreach ($this->claims as $mapping) {
            if ($mapping->defaultRelease) {
                $claims[] = $mapping->claim;
            }
        }

        return $claims;
    }
}
