<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Configuration;

/**
 * Configured parameters of the authorisation request (design §14). `max_age` is sent only when set.
 */
final readonly class AuthorizationParameters
{
    public function __construct(
        public string $scope,
        public ?string $prompt,
        public ?int $maxAge,
    ) {
    }
}
