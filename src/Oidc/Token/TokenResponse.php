<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Token;

use SensitiveParameter;

/**
 * The token response after its checks (design §14). Both tokens are live secrets and never logged.
 */
final readonly class TokenResponse
{
    public function __construct(
        #[SensitiveParameter] public string $idToken,
        #[SensitiveParameter] public string $accessToken,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [];
    }
}
