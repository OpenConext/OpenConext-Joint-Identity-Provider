<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Profile;

use DateTimeImmutable;

/**
 * What a profile hands the core after every check on the provider's messages passed (design §2).
 */
interface ProfileResult
{
    /**
     * The verified claim set: claim name to its string values.
     *
     * @return array<string, list<string>>
     */
    public function verifiedClaims(): array;

    /**
     * The hard expiry of the proof. A delivery-time recheck never extends it.
     */
    public function hardExpiry(): DateTimeImmutable;

    /**
     * Profile-owned data that the delivery-time recheck needs, kept with the transaction. It holds no
     * secrets and no raw claim values.
     *
     * @return array<string, string|int|null>
     */
    public function recheckState(): array;
}
