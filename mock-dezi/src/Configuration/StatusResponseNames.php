<?php

declare(strict_types=1);

namespace MockDezi\Configuration;

/**
 * PROVISIONAL names and values of the status answer (config/mock-dezi.yaml, status_response).
 */
final readonly class StatusResponseNames
{
    public function __construct(
        public string $idField,
        public string $statusField,
        public string $revokedAtField,
        public string $active,
        public string $revoked,
        public string $other,
    ) {
    }
}
