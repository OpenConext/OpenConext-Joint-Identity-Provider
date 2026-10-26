<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

use JointIdentityProvider\Core\Profile\ProfileConfiguration;

final readonly class DeziProfileConfiguration implements ProfileConfiguration
{
    /**
     * @param array<string, string> $envelopeAudiences client name => the envelope `aud` confirmed for it
     * @param list<string> $nullableClaims optional statement claims whose null the contract permits as absent
     */
    public function __construct(
        // The confirmed high-assurance value per claim (design §16); never assumed equal for both claims.
        public string $expectedLoaAuthn,
        public string $expectedLoaDezi,
        public DeziRevocationConfiguration $revocation,
        // The envelope claim that carries the sealed statement, as the CIBG's example messages show.
        public string $statementClaim,
        public SubjectAssociation $subjectAssociation,
        public array $envelopeAudiences,
        public array $nullableClaims,
    ) {
    }

    public function deliveryRecheckTimeoutSeconds(): int
    {
        return $this->revocation->timeoutSeconds;
    }
}
