<?php

declare(strict_types=1);

namespace MockDezi\Store\Record;

/**
 * The mock's own DEZI session. It is reused only for a request without prompt=login whose max_age allows it.
 */
final readonly class LoginSession
{
    public function __construct(
        public string $personId,
        public int $authTime,
        public int $expiresAt,
    ) {
    }
}
