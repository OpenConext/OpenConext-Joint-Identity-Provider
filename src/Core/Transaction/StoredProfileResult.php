<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Transaction;

use DateTimeImmutable;
use JointIdentityProvider\Core\Profile\ProfileResult;
use SensitiveParameter;

/**
 * A profile result as the transaction store keeps it: exactly what ProfileResult exposes.
 */
final readonly class StoredProfileResult implements ProfileResult
{
    /**
     * @param array<string, list<string>> $verifiedClaims
     * @param array<string, string|int|null> $recheckState
     */
    public function __construct(
        #[SensitiveParameter] private array $verifiedClaims,
        private DateTimeImmutable $hardExpiry,
        private array $recheckState,
    ) {
    }

    public function verifiedClaims(): array
    {
        return $this->verifiedClaims;
    }

    public function hardExpiry(): DateTimeImmutable
    {
        return $this->hardExpiry;
    }

    public function recheckState(): array
    {
        return $this->recheckState;
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['hardExpiry' => $this->hardExpiry];
    }
}
