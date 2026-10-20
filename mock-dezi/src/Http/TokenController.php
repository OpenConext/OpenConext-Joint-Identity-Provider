<?php

declare(strict_types=1);

namespace MockDezi\Http;

use MockDezi\Client\ClientAuthenticator;
use MockDezi\Configuration\ConfigurationLoader;
use MockDezi\Fixture\FixtureRepository;
use MockDezi\Message\IdTokenFactory;
use MockDezi\Message\Jose;
use MockDezi\Scenario\Endpoint;
use MockDezi\Scenario\Scenario;
use MockDezi\Store\Record\AccessToken;
use MockDezi\Store\State;
use MockDezi\Store\StateStore;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The token endpoint (design §14): client authentication, then a single-use code bound to the client, the
 * redirect URI and the PKCE S256 challenge. The code is consumed in the same locked step that checks it.
 */
final readonly class TokenController
{
    public function __construct(
        private ConfigurationLoader $loader,
        private FixtureRepository $fixtures,
        private StateStore $store,
        private ClientAuthenticator $authenticator,
        private IdTokenFactory $idTokens,
        private EndpointGuard $guard,
        private ClockInterface $clock,
    ) {
    }

    #[Route('/token', name: 'mock_dezi_token', methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $configuration = $this->loader->load();
        $failure = $this->guard->check(Endpoint::Token, $configuration->tokenEndpoint(), 'application/json', $request);
        if ($failure !== null) {
            return $failure;
        }
        if ($request->getContentTypeFormat() !== 'form') {
            return Responses::oauthError('invalid_request', 'the body must be application/x-www-form-urlencoded');
        }
        $form = [];
        foreach ($request->request->all() as $name => $value) {
            if (!is_string($value)) {
                return Responses::oauthError('invalid_request', sprintf('parameter %s must be a string', $name));
            }
            $form[$name] = $value;
        }
        $client = $configuration->client($form['client_id'] ?? '');
        if ($client === null) {
            return Responses::oauthError('invalid_client', 'unknown client_id', Response::HTTP_UNAUTHORIZED);
        }

        $now = $this->clock->now()->getTimestamp();
        $accessToken = Jose::randomToken();

        $outcome = $this->store->transaction(function (State $state) use (
            $configuration,
            $client,
            $form,
            $now,
            $accessToken,
        ): Response|array {
            $authenticationError = $this->authenticator->authenticate($configuration, $client, $form, $state, $now);
            if ($authenticationError !== null) {
                return Responses::oauthError('invalid_client', $authenticationError, Response::HTTP_UNAUTHORIZED);
            }
            if (($form['grant_type'] ?? null) !== 'authorization_code') {
                return Responses::oauthError('unsupported_grant_type', 'only authorization_code');
            }
            $key = hash('sha256', $form['code'] ?? '');
            $code = $state->codes[$key] ?? null;
            unset($state->codes[$key]);
            if ($code === null) {
                return Responses::oauthError('invalid_grant', 'unknown, expired or already used code');
            }
            if ($code->clientId !== $client->clientId || ($form['redirect_uri'] ?? null) !== $code->redirectUri) {
                return Responses::oauthError('invalid_grant', 'the code was issued to another client or redirect_uri');
            }
            $verifier = $form['code_verifier'] ?? '';
            if (
                preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $verifier) !== 1
                || !hash_equals($code->codeChallenge, Jose::base64Url(hash('sha256', $verifier, true)))
            ) {
                return Responses::oauthError('invalid_grant', 'code_verifier does not match the S256 code_challenge');
            }
            $person = $this->fixtures->person($code->personId);
            if ($person === null) {
                return Responses::oauthError('invalid_grant', 'the person no longer exists in the fixtures');
            }
            $subject = IdTokenFactory::pairwiseSubject($configuration, $client, $person);
            $state->accessTokens[hash('sha256', $accessToken)] = new AccessToken(
                clientId: $client->clientId,
                personId: $person->id,
                profileId: $code->profileId,
                subject: $subject,
                scenario: $code->scenario,
                expiresAt: $now + $configuration->accessTokenSeconds,
            );

            return [$code, $subject];
        });
        if ($outcome instanceof Response) {
            return $outcome;
        }
        [$code, $subject] = $outcome;

        switch ($code->scenario) {
            case Scenario::TokenServerError:
                return Responses::oauthError('server_error', 'mock scenario', Response::HTTP_INTERNAL_SERVER_ERROR);
            case Scenario::TokenInvalidClient:
                return Responses::oauthError('invalid_client', 'mock scenario', Response::HTTP_UNAUTHORIZED);
            case Scenario::TokenInvalidGrant:
                return Responses::oauthError('invalid_grant', 'mock scenario');
            default:
                break;
        }

        $body = [
            'access_token' => $accessToken,
            'token_type' => $code->scenario === Scenario::TokenTypeNotBearer ? 'N_A' : 'Bearer',
            'expires_in' => $configuration->accessTokenSeconds,
            'scope' => 'openid',
            'id_token' => $this->idTokens->create($configuration, $client, $code, $subject, $now),
        ];
        if ($code->scenario === Scenario::TokenWithoutIdToken) {
            unset($body['id_token']);
        }
        if ($code->scenario === Scenario::TokenWithoutAccessToken) {
            unset($body['access_token']);
        }

        return Responses::json($body);
    }
}
