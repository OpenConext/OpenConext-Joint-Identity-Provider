<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Profile;

use DateTimeImmutable;
use InvalidArgumentException;

/**
 * The outcome of a delivery-time recheck. A passed recheck is valid until the earlier of its own
 * validity and the result's hard expiry; renewing never extends the hard expiry.
 */
final readonly class RecheckResult
{
    private function __construct(
        public bool $passed,
        public ?ProfileResult $result,
        public ?DateTimeImmutable $validUntil,
        public ?string $failureType,
        public bool $restartable,
    ) {
    }

    public static function passed(ProfileResult $original, ProfileResult $renewed, DateTimeImmutable $validUntil): self
    {
        if ($renewed->hardExpiry() > $original->hardExpiry()) {
            throw new InvalidArgumentException('A recheck must not extend the hard expiry of a result.');
        }

        return new self(true, $renewed, min($validUntil, $renewed->hardExpiry()), null, false);
    }

    public static function failed(string $failureType, bool $restartable): self
    {
        return new self(false, null, null, $failureType, $restartable);
    }
}
