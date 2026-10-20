<?php

declare(strict_types=1);

namespace MockDezi\Http;

use MockDezi\Configuration\ConfigurationLoader;
use MockDezi\Configuration\MockConfiguration;
use MockDezi\Fixture\FixtureRepository;
use MockDezi\Message\Jose;
use MockDezi\Scenario\Endpoint;
use MockDezi\Scenario\StatementBehaviour;
use MockDezi\Store\State;
use MockDezi\Store\StateStore;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The status check per statement (design §15) at the path of specification v0.7 (/status/v1/verklaring/{id}).
 * The behaviour per statement comes from the admin API or a status scenario, else from the fixtures; an unknown
 * statement answers 404 as acceptance does. The endpoint mode of `status` applies to every statement.
 */
final readonly class StatusController
{
    public function __construct(
        private ConfigurationLoader $loader,
        private FixtureRepository $fixtures,
        private StateStore $store,
        private EndpointGuard $guard,
        private ClockInterface $clock,
    ) {
    }

    #[Route(
        MockConfiguration::STATUS_PATH_PREFIX . '{verklaringId}',
        name: 'mock_dezi_status',
        requirements: ['verklaringId' => '[^/]+'],
        methods: ['GET'],
    )]
    public function status(Request $request, string $verklaringId): Response
    {
        $configuration = $this->loader->load();
        $statusUrl = $configuration->statusUrl($verklaringId);
        $failure = $this->guard->check(Endpoint::Status, $statusUrl, 'application/json', $request);
        if ($failure !== null) {
            return $failure;
        }

        $behaviour = $request->query->has('redirected')
            ? StatementBehaviour::Active
            : $this->store->transaction(
                fn (State $state): StatementBehaviour => $state->statementBehaviours[$verklaringId]
                    ?? $this->fixtures->profileByVerklaringId($verklaringId)->status
                    ?? StatementBehaviour::NotFound,
            );
        $names = $configuration->statusNames;

        switch ($behaviour) {
            case StatementBehaviour::NotFound:
                return Responses::problem(Response::HTTP_NOT_FOUND, 'Not Found');
            case StatementBehaviour::BadRequest:
                return Responses::problem(Response::HTTP_BAD_REQUEST, 'Bad Request');
            case StatementBehaviour::ServerError:
                return Responses::problem(Response::HTTP_INTERNAL_SERVER_ERROR, 'Internal Server Error');
            case StatementBehaviour::Redirect:
                return Responses::redirectTo($statusUrl, ['redirected' => '1']);
            case StatementBehaviour::InvalidBody:
                return Responses::noStore(
                    new Response('mock: not JSON', Response::HTTP_OK, ['Content-Type' => 'application/json']),
                );
            case StatementBehaviour::Revoked:
                return Responses::json([
                    $names->idField => $verklaringId,
                    $names->statusField => $names->revoked,
                    $names->revokedAtField => $this->clock->now()->getTimestamp() - 60,
                ]);
            case StatementBehaviour::OtherStatus:
                return Responses::json([$names->idField => $verklaringId, $names->statusField => $names->other]);
            case StatementBehaviour::WrongId:
                return Responses::json([$names->idField => Jose::uuidV4(), $names->statusField => $names->active]);
            case StatementBehaviour::Timeout:
                sleep($configuration->timeoutDelaySeconds);
                // Answer active after the delay: a client that waits this long would wrongly accept.
                return Responses::json([$names->idField => $verklaringId, $names->statusField => $names->active]);
            case StatementBehaviour::Active:
                return Responses::json([$names->idField => $verklaringId, $names->statusField => $names->active]);
        }
    }

    /**
     * The links inside the statement (`status_uri`, `revocatie_controle_uri`). JIP must never call them (design
     * §15); every call is counted in the state and refused.
     */
    #[Route(
        '/statement-link/{kind}/{verklaringId}',
        name: 'mock_dezi_statement_link',
        requirements: ['kind' => 'status|revocatie', 'verklaringId' => '[^/]+'],
        methods: ['GET', 'POST'],
    )]
    public function statementLink(string $kind, string $verklaringId): Response
    {
        $this->store->transaction(static function (State $state) use ($kind, $verklaringId): void {
            $key = $kind . '/' . $verklaringId;
            $state->statementLinkCalls[$key] = ($state->statementLinkCalls[$key] ?? 0) + 1;
        });

        return Responses::problem(Response::HTTP_GONE, 'Mock: a client must not call the link inside the statement');
    }
}
