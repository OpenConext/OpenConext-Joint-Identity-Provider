<?php

declare(strict_types=1);

namespace MockDezi\Store\Record;

use MockDezi\Scenario\Scenario;

/**
 * A single-use authorisation code with everything the token endpoint needs.
 */
final readonly class AuthorizationCode
{
    public function __construct(
        public string $clientId,
        public string $redirectUri,
        public string $codeChallenge,
        public string $nonce,
        public string $personId,
        public string $profileId,
        public int $authTime,
        public int $attemptReceivedAt,
        public Scenario $scenario,
        public int $expiresAt,
    ) {
    }
}
