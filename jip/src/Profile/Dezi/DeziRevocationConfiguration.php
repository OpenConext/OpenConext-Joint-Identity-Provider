<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

/**
 * The revocation decision settings (design §15, §17 `provider.revocation`). This version supports the
 * live status check only.
 */
final readonly class DeziRevocationConfiguration
{
    public const string MODE_STATUS_CHECK = 'status_check';
    public const string MODE_STATUS_CHECK_WITH_LIST = 'status_check_with_list';
    public const string STATUS_ADDRESS_PLACEHOLDER = '{verklaring_id}';

    public function __construct(
        public string $mode,
        public string $statusAddressTemplate,
        public int $timeoutSeconds,
        public int $decisionValiditySeconds,
    ) {
    }
}
