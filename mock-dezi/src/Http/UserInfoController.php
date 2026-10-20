<?php

declare(strict_types=1);

namespace MockDezi\Http;

use MockDezi\Configuration\ConfigurationLoader;
use MockDezi\Configuration\MockConfiguration;
use MockDezi\Fixture\FixtureRepository;
use MockDezi\Message\Jose;
use MockDezi\Message\UserInfoFactory;
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
 * The UserInfo endpoint: the encrypted, sealed statement for the access token's profile (design §14).
 * A status scenario issues a fresh verklaring_id with its status behaviour, so it affects no other login.
 */
final readonly class UserInfoController
{
    // PROVISIONAL: the content type of DEZI's UserInfo response is not given in the design.
    public const string CONTENT_TYPE = 'application/jwt';

    public function __construct(
        private ConfigurationLoader $loader,
        private FixtureRepository $fixtures,
        private StateStore $store,
        private UserInfoFactory $userInfo,
        private EndpointGuard $guard,
        private ClockInterface $clock,
    ) {
    }

    #[Route('/userinfo', name: 'mock_dezi_userinfo', methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $configuration = $this->loader->load();
        $failure = $this->guard->check(
            Endpoint::UserInfo,
            $configuration->url(MockConfiguration::USERINFO_PATH),
            self::CONTENT_TYPE,
            $request,
        );
        if ($failure !== null) {
            return $failure;
        }
        $authorization = $request->headers->get('Authorization', '') ?? '';
        if (preg_match('/^Bearer ([A-Za-z0-9\-._~+\/]+=*)$/', $authorization, $matches) !== 1) {
            return self::invalidToken('a Bearer access token is required');
        }
        $tokenKey = hash('sha256', $matches[1]);

        $issued = $this->store->transaction(static function (State $state) use ($tokenKey): ?array {
            $token = $state->accessTokens[$tokenKey] ?? null;
            if ($token === null) {
                return null;
            }
            $behaviour = $token->scenario->statementBehaviour();
            $verklaringId = null;
            if ($behaviour !== null) {
                $verklaringId = Jose::uuidV4();
                $state->statementBehaviours[$verklaringId] = $behaviour;
            }

            return [$token, $verklaringId];
        });
        if ($issued === null) {
            return self::invalidToken('unknown or expired access token');
        }
        /** @var AccessToken $token */
        [$token, $freshVerklaringId] = $issued;
        if ($token->scenario === Scenario::UserInfoServerError) {
            return Responses::oauthError('server_error', 'mock scenario', Response::HTTP_INTERNAL_SERVER_ERROR);
        }
        $client = $configuration->client($token->clientId);
        $person = $this->fixtures->person($token->personId);
        $profile = $person?->profile($token->profileId);
        if ($client === null || $person === null || $profile === null) {
            return self::invalidToken('the token\'s client or person no longer exists');
        }

        $body = $this->userInfo->create(
            $configuration,
            $client,
            $person,
            $profile,
            $freshVerklaringId ?? $profile->verklaringId,
            $token->subject,
            $token->scenario,
            $this->clock->now()->getTimestamp(),
        );

        return Responses::noStore(new Response($body, Response::HTTP_OK, ['Content-Type' => self::CONTENT_TYPE]));
    }

    private static function invalidToken(string $description): Response
    {
        return Responses::oauthError('invalid_token', $description, Response::HTTP_UNAUTHORIZED);
    }
}
