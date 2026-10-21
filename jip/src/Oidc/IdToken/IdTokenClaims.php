<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\IdToken;

/**
 * The claims of an ID token that passed every check of design §14.
 */
final readonly class IdTokenClaims
{
    /**
     * @param array<string, mixed> $claims all claims of the token
     */
    public function __construct(
        public string $subject,
        public int $authTime,
        public array $claims,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['authTime' => $this->authTime];
    }
}
