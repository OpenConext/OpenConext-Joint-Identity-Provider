<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

use RuntimeException;
use Throwable;

/**
 * A failed DEZI check. The detail names the check that failed and never holds a received value.
 */
final class DeziFailure extends RuntimeException
{
    public function __construct(
        public readonly DeziFailureType $type,
        public readonly string $detail,
        ?Throwable $previous = null,
    ) {
        parent::__construct($type->value . ': ' . $detail, 0, $previous);
    }
}
