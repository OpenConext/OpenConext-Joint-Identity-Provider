<?php

declare(strict_types=1);

namespace MockDezi\Fixture;

use MockDezi\Scenario\StatementBehaviour;

/**
 * One DEZI profile: one subscriber and at most one role (design §6). PROVISIONAL fixture data.
 */
final readonly class Profile
{
    public function __construct(
        public string $id,
        public string $label,
        public string $verklaringId,
        public string $abonneeNummer,
        public string $abonneeNaam,
        public ?string $rolCode,
        public ?string $rolNaam,
        public ?string $rolCodeBron,
        public StatementBehaviour $status,
    ) {
    }
}
