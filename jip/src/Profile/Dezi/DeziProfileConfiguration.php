<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

use JointIdentityProvider\Core\Profile\ProfileConfiguration;

final readonly class DeziProfileConfiguration implements ProfileConfiguration
{
    public function __construct(
        // The confirmed high-assurance value per claim (design §16); never assumed equal for both claims.
        public string $expectedLoaAuthn,
        public string $expectedLoaDezi,
        public DeziRevocationConfiguration $revocation,
    ) {
    }

    public function deliveryRecheckTimeoutSeconds(): int
    {
        return $this->revocation->timeoutSeconds;
    }
}
