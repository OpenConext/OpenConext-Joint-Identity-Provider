<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

use DateTimeImmutable;
use SensitiveParameter;

/**
 * The envelope and statement after every check of design §14 and §16, before the revocation decision.
 */
final readonly class VerifiedProof
{
    /**
     * @param array<string, list<string>> $claims releasable statement claims, exactly as DEZI sent them
     */
    public function __construct(
        #[SensitiveParameter] public array $claims,
        public string $verklaringId,
        // The earlier of the envelope's and the statement's exp: the proof's hard expiry.
        public DateTimeImmutable $hardExpiry,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['hardExpiry' => $this->hardExpiry];
    }
}
