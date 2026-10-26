<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Configuration;

final readonly class SigningKey
{
    public function __construct(
        public KeyPair $keyPair,
        public int $assertionLifetimeSeconds,
    ) {
    }
}
