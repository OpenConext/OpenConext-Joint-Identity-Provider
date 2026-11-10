<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

use JointIdentityProvider\Core\Profile\ProfileConfiguration;
use JointIdentityProvider\Oidc\Configuration\OidcProviderConfiguration;
use JointIdentityProvider\Oidc\Configuration\TrustSettings;

/**
 * The validated `provider` block: the profile's name and its own settings, the OIDC client's settings,
 * and the trust anchors per message type (design §14, §17).
 */
final readonly class ProviderConfiguration
{
    public function __construct(
        public string $profile,
        public OidcProviderConfiguration $oidc,
        public TrustSettings $trust,
        public int $certificateExpiryWarningDays,
        public ProfileConfiguration $profileConfiguration,
    ) {
    }
}
