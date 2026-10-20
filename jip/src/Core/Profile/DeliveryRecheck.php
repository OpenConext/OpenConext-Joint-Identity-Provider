<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Profile;

use DateTimeImmutable;

/**
 * The profile's check when the result is delivered (design §2, §13). For DEZI it renews an aged
 * revocation decision.
 */
interface DeliveryRecheck
{
    /**
     * Makes at most one outgoing request, within ProfileConfiguration::deliveryRecheckTimeoutSeconds().
     */
    public function recheck(ProfileResult $result, DateTimeImmutable $now): RecheckResult;
}
