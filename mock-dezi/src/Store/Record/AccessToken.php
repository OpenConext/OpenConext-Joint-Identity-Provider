<?php

declare(strict_types=1);

namespace MockDezi\Store\Record;

use MockDezi\Scenario\Scenario;

final readonly class AccessToken
{
    public function __construct(
        public string $clientId,
        public string $personId,
        public string $profileId,
        public string $subject,
        public Scenario $scenario,
        public int $expiresAt,
    ) {
    }
}
