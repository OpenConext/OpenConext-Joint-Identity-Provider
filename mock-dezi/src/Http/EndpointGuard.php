<?php

declare(strict_types=1);

namespace MockDezi\Http;

use MockDezi\Configuration\ConfigurationLoader;
use MockDezi\Scenario\Endpoint;
use MockDezi\Scenario\EndpointMode;
use MockDezi\Store\State;
use MockDezi\Store\StateStore;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Applies the endpoint mode that the admin API selected. Endpoint-specific modes are left to the controller.
 */
final readonly class EndpointGuard
{
    public function __construct(
        private StateStore $store,
        private ConfigurationLoader $loader,
    ) {
    }

    public function mode(Endpoint $endpoint): EndpointMode
    {
        return $this->store->transaction(static fn (State $state): EndpointMode => $state->endpointMode($endpoint));
    }

    /**
     * A failure response for the common modes, or null to answer normally. `timeout` waits first, outside the
     * state lock, and then answers normally.
     */
    public function failure(
        EndpointMode $mode,
        string $redirectTarget,
        string $contentType,
        Request $request,
        int $redirectStatus = Response::HTTP_FOUND,
    ): ?Response {
        switch ($mode) {
            case EndpointMode::ServerError:
                return Responses::json(['error' => 'server_error'], Response::HTTP_INTERNAL_SERVER_ERROR);
            case EndpointMode::Unavailable:
                $response = Responses::json(['error' => 'temporarily_unavailable'], Response::HTTP_SERVICE_UNAVAILABLE);
                $response->headers->set('Retry-After', '30');

                return $response;
            case EndpointMode::Redirect:
                return $request->query->get('redirected') === '1'
                    ? null
                    : Responses::redirectTo($redirectTarget, ['redirected' => '1'], $redirectStatus);
            case EndpointMode::InvalidBody:
                return Responses::noStore(new Response('<html>mock: not the expected body</html>', 200, [
                    'Content-Type' => $contentType,
                ]));
            case EndpointMode::Timeout:
                sleep($this->loader->load()->timeoutDelaySeconds);

                return null;
            default:
                return null;
        }
    }

    /**
     * Mode and failure in one step, for endpoints without modes of their own.
     */
    public function check(
        Endpoint $endpoint,
        string $redirectTarget,
        string $contentType,
        Request $request,
    ): ?Response {
        return $this->failure(
            $this->mode($endpoint),
            $redirectTarget,
            $contentType,
            $request,
            $request->isMethod('POST') ? Response::HTTP_TEMPORARY_REDIRECT : Response::HTTP_FOUND,
        );
    }
}
