<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Profile;

/**
 * The validated, profile-owned part of the `provider` block.
 */
interface ProfileConfiguration
{
    /**
     * The longest outgoing request the delivery-time recheck may make. It must fit within half of
     * EngineBlock's call timeout (design §9 item 13, §13).
     */
    public function deliveryRecheckTimeoutSeconds(): int;
}
