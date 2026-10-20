<?php

declare(strict_types=1);

namespace MockDezi\Store;

use MockDezi\Scenario\Endpoint;
use MockDezi\Scenario\EndpointMode;
use MockDezi\Scenario\Scenario;
use MockDezi\Scenario\StatementBehaviour;
use MockDezi\Store\Record\AccessToken;
use MockDezi\Store\Record\AuthorizationCode;
use MockDezi\Store\Record\AuthorizationRequest;
use MockDezi\Store\Record\LoginSession;

/**
 * Everything the mock remembers between requests. Changed only inside StateStore::transaction().
 */
final class State
{
    /** @var array<string, AuthorizationRequest> */
    public array $authorizationRequests = [];

    /** @var array<string, LoginSession> keyed by the SHA-256 of the session cookie value */
    public array $sessions = [];

    /** @var array<string, AuthorizationCode> keyed by the SHA-256 of the code */
    public array $codes = [];

    /** @var array<string, AccessToken> keyed by the SHA-256 of the access token */
    public array $accessTokens = [];

    /** @var array<string, int> client assertion jti => the time until which it stays refused */
    public array $usedAssertionIds = [];

    /** @var array<string, StatementBehaviour> verklaring_id => status behaviour, overriding the fixtures */
    public array $statementBehaviours = [];

    /** @var array<string, EndpointMode> endpoint name => mode; absent means available */
    public array $endpointModes = [];

    /** @var array<string, int> statement link path => number of calls; JIP must never call these */
    public array $statementLinkCalls = [];

    public Scenario $defaultScenario = Scenario::Success;

    public function endpointMode(Endpoint $endpoint): EndpointMode
    {
        return $this->endpointModes[$endpoint->value] ?? EndpointMode::Available;
    }

    public function clear(): void
    {
        $this->authorizationRequests = [];
        $this->sessions = [];
        $this->codes = [];
        $this->accessTokens = [];
        $this->usedAssertionIds = [];
        $this->statementBehaviours = [];
        $this->endpointModes = [];
        $this->statementLinkCalls = [];
        $this->defaultScenario = Scenario::Success;
    }

    public function prune(int $now): void
    {
        $this->authorizationRequests = array_filter(
            $this->authorizationRequests,
            static fn (AuthorizationRequest $record): bool => $record->expiresAt > $now,
        );
        $this->sessions = array_filter(
            $this->sessions,
            static fn (LoginSession $record): bool => $record->expiresAt > $now,
        );
        $this->codes = array_filter(
            $this->codes,
            static fn (AuthorizationCode $record): bool => $record->expiresAt > $now,
        );
        $this->accessTokens = array_filter(
            $this->accessTokens,
            static fn (AccessToken $record): bool => $record->expiresAt > $now,
        );
        $this->usedAssertionIds = array_filter($this->usedAssertionIds, static fn (int $until): bool => $until > $now);
    }
}
