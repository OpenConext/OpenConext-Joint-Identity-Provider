<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Profile;

/**
 * The profile's verdict on a login that passed the standard OIDC checks. A verified outcome is not yet a
 * success: the core still applies its own checks before a transaction succeeds.
 */
final readonly class ProfileOutcome
{
    private function __construct(
        public ?ProfileResult $result,
        public ?string $failureType,
        public bool $restartable,
        public string $detail,
    ) {
    }

    public static function verified(ProfileResult $result): self
    {
        return new self($result, null, false, '');
    }

    /**
     * @param string $detail names the failed check; never a received value
     */
    public static function failed(string $failureType, bool $restartable, string $detail): self
    {
        return new self(null, $failureType, $restartable, $detail);
    }
}
