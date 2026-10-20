<?php

declare(strict_types=1);

namespace MockDezi\Store\Record;

use MockDezi\Scenario\Scenario;

/**
 * A received authorisation request, kept until the login is completed or the request expires.
 */
final readonly class AuthorizationRequest
{
    public function __construct(
        public string $id,
        public string $clientId,
        public string $redirectUri,
        public string $state,
        public string $nonce,
        public string $codeChallenge,
        public int $receivedAt,
        public int $expiresAt,
        public ?string $personId = null,
        public ?int $authTime = null,
        public Scenario $scenario = Scenario::Success,
    ) {
    }

    public function authenticated(string $personId, int $authTime, Scenario $scenario): self
    {
        return new self(
            $this->id,
            $this->clientId,
            $this->redirectUri,
            $this->state,
            $this->nonce,
            $this->codeChallenge,
            $this->receivedAt,
            $this->expiresAt,
            $personId,
            $authTime,
            $scenario,
        );
    }
}
