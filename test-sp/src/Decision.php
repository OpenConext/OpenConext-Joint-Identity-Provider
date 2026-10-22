<?php

declare(strict_types=1);

namespace JointIdentityProvider\TestSp;

/**
 * The outcome of {@see AccessDecision}. The reason is a fixed text without attribute values, so it can be logged.
 */
final readonly class Decision
{
    private function __construct(
        public Access $access,
        public string $reason,
        public ?string $deziNumber = null,
        public ?string $subscriber = null,
        public ?string $role = null,
    ) {
    }

    public static function dezi(string $deziNumber, string $subscriber, ?string $role, string $reason): self
    {
        return new self(Access::Dezi, $reason, $deziNumber, $subscriber, $role);
    }

    public static function organisation(string $reason): self
    {
        return new self(Access::Organisation, $reason);
    }

    public static function refused(string $reason): self
    {
        return new self(Access::Refused, $reason);
    }
}
