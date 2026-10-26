<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Transaction;

use DateTimeImmutable;
use SensitiveParameter;

/**
 * The values `/interrupt` creates for one attempt at the provider (design §13). All are live secrets
 * and are never logged.
 */
final readonly class ProviderAttempt
{
    public function __construct(
        #[SensitiveParameter] public string $oidcState,
        #[SensitiveParameter] public string $oidcNonce,
        #[SensitiveParameter] public string $pkceVerifier,
        #[SensitiveParameter] public string $cookieValue,
        public DateTimeImmutable $startedAt,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['startedAt' => $this->startedAt];
    }
}
