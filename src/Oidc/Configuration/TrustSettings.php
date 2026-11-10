<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Configuration;

/**
 * Approved signing-key addresses, expected issuers and timing policy for provider messages.
 */
final readonly class TrustSettings
{
    public const string ID_TOKEN = 'id_token';

    /**
     * @param array<string, string> $approvedKeyAddresses message type => the only key address for it
     * @param array<string, string> $expectedIssuers message type => expected `iss`
     */
    public function __construct(
        public array $approvedKeyAddresses,
        public array $expectedIssuers,
        public int $clockSkewSeconds,
        public int $keyCacheSeconds,
        public int $keyRefetchMinIntervalSeconds,
    ) {
    }
}
