<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc;

use DateTimeImmutable;
use JointIdentityProvider\Oidc\Configuration\ClientConfiguration;
use JointIdentityProvider\Oidc\Discovery\ProviderMetadata;
use JointIdentityProvider\Oidc\IdToken\IdTokenClaims;
use SensitiveParameter;

/**
 * The validated outcome of the standard OIDC steps (design §14, callback to ID token), handed to the
 * provider profile. It proves nothing about the profile's own messages.
 */
final readonly class AuthenticatedLogin
{
    public function __construct(
        public ClientConfiguration $client,
        public ProviderMetadata $metadata,
        public IdTokenClaims $idToken,
        #[SensitiveParameter] public string $accessToken,
        public DateTimeImmutable $attemptStartedAt,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['client' => $this->client->name, 'attemptStartedAt' => $this->attemptStartedAt];
    }
}
