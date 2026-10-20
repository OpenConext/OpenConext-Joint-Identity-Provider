<?php

declare(strict_types=1);

namespace MockDezi\Http;

use MockDezi\Fixture\FixtureRepository;
use MockDezi\Scenario\Endpoint;
use MockDezi\Scenario\EndpointMode;
use MockDezi\Scenario\Scenario;
use MockDezi\Scenario\StatementBehaviour;
use MockDezi\Store\State;
use MockDezi\Store\StateStore;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Throwable;

/**
 * Scenario selection and reset for developers and tests. Changes require a JSON body, so a browser form on another
 * site cannot send them. MOCK ONLY: never expose this application outside local development.
 */
final readonly class AdminController
{
    public function __construct(
        private StateStore $store,
        private FixtureRepository $fixtures,
    ) {
    }

    #[Route('/mock/scenarios', name: 'mock_dezi_admin_scenarios', methods: ['GET'])]
    public function scenarios(): Response
    {
        $endpoints = [];
        foreach (Endpoint::cases() as $endpoint) {
            foreach ($endpoint->modes() as $mode) {
                $endpoints[$endpoint->value][$mode->value] = $mode->description();
            }
        }
        $persons = [];
        foreach ($this->fixtures->persons() as $person) {
            $profiles = [];
            foreach ($person->profiles as $profile) {
                $profiles[] = [
                    'id' => $profile->id,
                    'verklaring_id' => $profile->verklaringId,
                    'abonnee_nummer' => $profile->abonneeNummer,
                    'rol_code' => $profile->rolCode,
                    'status' => $profile->status->value,
                ];
            }
            $persons[$person->id] = [
                'description' => $person->description,
                'dezi_nummer' => $person->deziNummer,
                'profiles' => $profiles,
            ];
        }

        return Responses::jsonResponse([
            'scenarios' => array_map(static fn (Scenario $scenario): array => [
                'name' => $scenario->value,
                'step' => $scenario->step(),
                'jip_must_accept' => $scenario->isAccepted(),
                'description' => $scenario->description(),
            ], Scenario::cases()),
            'statement_behaviours' => array_combine(
                StatementBehaviour::values(),
                array_map(static fn (StatementBehaviour $b): string => $b->description(), StatementBehaviour::cases()),
            ),
            'endpoint_modes' => $endpoints,
            'persons' => $persons,
        ]);
    }

    #[Route('/mock/state', name: 'mock_dezi_admin_state', methods: ['GET'])]
    public function state(): Response
    {
        return Responses::jsonResponse($this->store->transaction(static fn (State $state): array => [
            'default_scenario' => $state->defaultScenario->value,
            'endpoint_modes' => array_map(
                static fn (EndpointMode $mode): string => $mode->value,
                $state->endpointModes,
            ),
            'statement_behaviours' => array_map(
                static fn (StatementBehaviour $behaviour): string => $behaviour->value,
                $state->statementBehaviours,
            ),
            'statement_link_calls' => $state->statementLinkCalls,
            'pending_logins' => count($state->authorizationRequests),
            'sessions' => count($state->sessions),
            'unused_codes' => count($state->codes),
            'access_tokens' => count($state->accessTokens),
            'used_client_assertion_ids' => count($state->usedAssertionIds),
        ]));
    }

    #[Route('/mock/default-scenario', name: 'mock_dezi_admin_default_scenario', methods: ['PUT'])]
    public function defaultScenario(Request $request): Response
    {
        $body = self::body($request);
        if ($body instanceof Response) {
            return $body;
        }
        $scenario = is_string($body['scenario'] ?? null) ? Scenario::tryFrom($body['scenario']) : null;
        if ($scenario === null) {
            return self::badRequest('"scenario" must be one of GET /mock/scenarios');
        }
        $this->store->transaction(static function (State $state) use ($scenario): void {
            $state->defaultScenario = $scenario;
        });

        return $this->state();
    }

    #[Route('/mock/endpoints/{endpoint}', name: 'mock_dezi_admin_endpoint', methods: ['PUT'])]
    public function endpoint(Request $request, string $endpoint): Response
    {
        $body = self::body($request);
        if ($body instanceof Response) {
            return $body;
        }
        $target = Endpoint::tryFrom($endpoint);
        $mode = is_string($body['mode'] ?? null) ? EndpointMode::tryFrom($body['mode']) : null;
        if ($target === null || $mode === null || !$target->allows($mode)) {
            return self::badRequest('unknown endpoint, or a mode it does not support (GET /mock/scenarios)');
        }
        $this->store->transaction(static function (State $state) use ($target, $mode): void {
            if ($mode === EndpointMode::Available) {
                unset($state->endpointModes[$target->value]);
            } else {
                $state->endpointModes[$target->value] = $mode;
            }
        });

        return $this->state();
    }

    #[Route(
        '/mock/statements/{verklaringId}',
        name: 'mock_dezi_admin_statement',
        requirements: ['verklaringId' => '[^/]+'],
        methods: ['PUT'],
    )]
    public function statement(Request $request, string $verklaringId): Response
    {
        $body = self::body($request);
        if ($body instanceof Response) {
            return $body;
        }
        $behaviour = is_string($body['behaviour'] ?? null) ? StatementBehaviour::tryFrom($body['behaviour']) : null;
        if ($behaviour === null) {
            return self::badRequest('"behaviour" must be one of GET /mock/scenarios statement_behaviours');
        }
        $this->store->transaction(static function (State $state) use ($verklaringId, $behaviour): void {
            $state->statementBehaviours[$verklaringId] = $behaviour;
        });

        return $this->state();
    }

    #[Route('/mock/reset', name: 'mock_dezi_admin_reset', methods: ['POST'])]
    public function reset(Request $request): Response
    {
        $body = self::body($request);
        if ($body instanceof Response) {
            return $body;
        }
        $this->store->reset();

        return $this->state();
    }

    /**
     * @return array<mixed>|Response
     */
    private static function body(Request $request): array|Response
    {
        if ($request->getContentTypeFormat() !== 'json') {
            return Responses::jsonResponse(
                ['error' => 'Content-Type must be application/json'],
                Response::HTTP_UNSUPPORTED_MEDIA_TYPE,
            );
        }
        try {
            $body = $request->getContent() === '' ? [] : $request->toArray();
        } catch (Throwable) {
            return self::badRequest('the body must be a JSON object');
        }

        return $body;
    }

    private static function badRequest(string $message): Response
    {
        return Responses::jsonResponse(['error' => $message], Response::HTTP_BAD_REQUEST);
    }
}
