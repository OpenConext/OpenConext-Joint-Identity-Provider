<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Jose;

/**
 * A JWS whose RS256 signature verified with a key from its message type's approved key address.
 */
final readonly class VerifiedMessage
{
    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public array $header,
        public array $claims,
    ) {
    }
}
