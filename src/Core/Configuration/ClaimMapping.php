<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

final readonly class ClaimMapping
{
    public function __construct(
        public string $claim,
        public string $attribute,
        public bool $required,
        public bool $defaultRelease,
    ) {
    }
}
