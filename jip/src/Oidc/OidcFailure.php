<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc;

use RuntimeException;
use Throwable;

/**
 * A failed OIDC step. The detail names the check that failed and never holds a received value.
 */
final class OidcFailure extends RuntimeException
{
    public function __construct(
        public readonly OidcFailureType $type,
        public readonly string $detail,
        ?Throwable $previous = null,
    ) {
        parent::__construct($type->value . ': ' . $detail, 0, $previous);
    }
}
