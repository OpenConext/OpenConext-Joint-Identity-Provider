<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

use JointIdentityProvider\Core\Profile\ProfileConfiguration;
use JointIdentityProvider\Oidc\Configuration\OidcProviderConfiguration;

/**
 * The validated `provider` block: the profile's name and its own settings, the OIDC client's settings,
 * and the trust anchors per message type (design §14, §17).
 */
final readonly class ProviderConfiguration
{
    public const string ID_TOKEN = 'id_token';

    /**
     * @param array<string, string> $approvedKeyAddresses message type => the only key address for it
     * @param array<string, string> $expectedIssuers message type => expected `iss`
     */
    public function __construct(
        public string $profile,
        public OidcProviderConfiguration $oidc,
        public array $approvedKeyAddresses,
        public array $expectedIssuers,
        public int $clockSkewSeconds,
        public int $keyCacheSeconds,
        public int $keyRefetchMinIntervalSeconds,
        public int $certificateExpiryWarningDays,
        public ProfileConfiguration $profileConfiguration,
    ) {
    }
}
