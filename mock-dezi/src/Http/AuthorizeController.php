<?php

declare(strict_types=1);

namespace MockDezi\Http;

use MockDezi\Configuration\ConfigurationLoader;
use MockDezi\Fixture\FixtureRepository;
use MockDezi\Fixture\Person;
use MockDezi\Fixture\Profile;
use MockDezi\Message\Jose;
use MockDezi\Scenario\Scenario;
use MockDezi\Store\Record\AuthorizationCode;
use MockDezi\Store\Record\AuthorizationRequest;
use MockDezi\Store\Record\LoginSession;
use MockDezi\Store\State;
use MockDezi\Store\StateStore;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The authorisation endpoint and the simulated DEZI login (design §3 step 4, §14).
 *
 * Every request with prompt=login or max_age=0 shows the login page, so auth_time is the moment of this login.
 * Without them, the mock's own session is reused within max_age, as a real provider would; JIP must then refuse
 * the earlier auth_time. A person with more than one profile chooses one after logging in.
 */
final readonly class AuthorizeController
{
    public const string SESSION_COOKIE = 'mock_dezi_session';
    private const array SUPPORTED_PROMPTS = ['login', 'none', 'consent', 'select_account'];

    public function __construct(
        private ConfigurationLoader $loader,
        private FixtureRepository $fixtures,
        private StateStore $store,
        private ClockInterface $clock,
    ) {
    }

    #[Route('/authorize', name: 'mock_dezi_authorize', methods: ['GET'])]
    public function authorize(Request $request): Response
    {
        $configuration = $this->loader->load();
        $query = $request->query;
        $client = $configuration->client($query->getString('client_id'));
        $redirectUri = $query->getString('redirect_uri');
        if ($client === null || !$client->allowsRedirectUri($redirectUri)) {
            // Never redirect to an unverified address (RFC 6749 §4.1.2.1).
            return Html::error('Unknown client_id, or a redirect_uri that the client did not register.');
        }

        $state = $query->getString('state');
        $error = $this->requestError($request);
        if ($error !== null) {
            return Responses::redirectTo($redirectUri, ['error' => $error[0], 'error_description' => $error[1]] + (
                $state === '' ? [] : ['state' => $state]
            ));
        }

        $prompts = self::words($query->getString('prompt'));
        $maxAge = $query->has('max_age') ? (int) $query->getString('max_age') : null;
        $freshLogin = in_array('login', $prompts, true) || $maxAge === 0;
        $now = $this->clock->now()->getTimestamp();
        $sessionKey = self::hash($request->cookies->getString(self::SESSION_COOKIE));

        $outcome = $this->store->transaction(function (State $stored) use (
            $configuration,
            $client,
            $redirectUri,
            $state,
            $query,
            $freshLogin,
            $maxAge,
            $prompts,
            $sessionKey,
            $now,
        ): AuthorizationRequest|string {
            $session = $freshLogin ? null : ($stored->sessions[$sessionKey] ?? null);
            if ($session !== null && $maxAge !== null && $now - $session->authTime > $maxAge) {
                $session = null;
            }
            if ($session === null && in_array('none', $prompts, true)) {
                return 'login_required';
            }
            $authorization = new AuthorizationRequest(
                id: Jose::randomToken(),
                clientId: $client->clientId,
                redirectUri: $redirectUri,
                state: $state,
                nonce: $query->getString('nonce'),
                codeChallenge: $query->getString('code_challenge'),
                receivedAt: $now,
                expiresAt: $now + $configuration->authorizationRequestSeconds,
            );
            if ($session !== null) {
                $authorization = $authorization->authenticated(
                    $session->personId,
                    $session->authTime,
                    $stored->defaultScenario,
                );
            }

            return $stored->authorizationRequests[$authorization->id] = $authorization;
        });

        if ($outcome === 'login_required') {
            return Responses::redirectTo($redirectUri, [
                'error' => 'login_required',
                'error_description' => 'prompt=none and no usable mock DEZI session',
                'state' => $state,
            ]);
        }
        if ($outcome->personId !== null) {
            $person = $this->fixtures->person($outcome->personId);

            return $person === null ? Html::error('The session\'s person no longer exists.') : $this->afterLogin(
                $outcome,
                $person,
            );
        }

        return $this->loginPage($outcome);
    }

    #[Route('/authorize/login', name: 'mock_dezi_login', methods: ['POST'])]
    public function login(Request $request): Response
    {
        $authorization = $this->pendingRequest($request);
        if ($authorization === null) {
            return Html::error('Unknown or expired login. Start again at the client.');
        }
        if ($request->request->getString('action') === 'cancel') {
            return $this->cancel($authorization);
        }
        $person = $this->fixtures->person($request->request->getString('person'));
        if ($person === null) {
            return Html::error('Choose a person.');
        }
        $scenarioName = $request->request->getString('scenario');
        $scenario = $scenarioName === ''
            ? $this->store->transaction(static fn (State $state): Scenario => $state->defaultScenario)
            : Scenario::tryFrom($scenarioName);
        if ($scenario === null) {
            return Html::error('Unknown scenario.');
        }

        $configuration = $this->loader->load();
        $now = $this->clock->now()->getTimestamp();
        $sessionValue = Jose::randomToken();
        $authenticated = $authorization->authenticated($person->id, $now, $scenario);
        $pending = $this->store->transaction(static function (State $state) use (
            $authenticated,
            $person,
            $sessionValue,
            $now,
            $configuration,
        ): bool {
            if (!isset($state->authorizationRequests[$authenticated->id])) {
                return false;
            }
            $state->authorizationRequests[$authenticated->id] = $authenticated;
            $state->sessions[self::hash($sessionValue)] = new LoginSession(
                $person->id,
                $now,
                $now + $configuration->sessionSeconds,
            );

            return true;
        });
        if (!$pending) {
            return Html::error('Unknown, expired or already completed login. Start again at the client.');
        }

        $response = $this->afterLogin($authenticated, $person);
        $response->headers->setCookie(
            Cookie::create(self::SESSION_COOKIE, $sessionValue)
                ->withExpires($now + $configuration->sessionSeconds)
                ->withPath('/')
                ->withSecure(true)
                ->withHttpOnly(true)
                ->withSameSite(Cookie::SAMESITE_LAX),
        );

        return $response;
    }

    #[Route('/authorize/profile', name: 'mock_dezi_profile', methods: ['POST'])]
    public function profile(Request $request): Response
    {
        $authorization = $this->pendingRequest($request);
        if ($authorization === null || $authorization->personId === null) {
            return Html::error('Unknown or expired login. Start again at the client.');
        }
        if ($request->request->getString('action') === 'cancel') {
            return $this->cancel($authorization);
        }
        $person = $this->fixtures->person($authorization->personId);
        $profile = $person?->profile($request->request->getString('profile'));
        if ($person === null || $profile === null) {
            return Html::error('Choose one of the person\'s profiles.');
        }

        return $this->complete($authorization, $person, $profile);
    }

    private function afterLogin(AuthorizationRequest $authorization, Person $person): Response
    {
        if (count($person->profiles) === 1) {
            return $this->complete($authorization, $person, $person->profiles[0]);
        }

        $options = '';
        foreach ($person->profiles as $profile) {
            $options .= sprintf(
                '<label><input type="radio" name="profile" value="%s" required> %s (subscriber %s, role %s)</label>',
                Html::e($profile->id),
                Html::e($profile->label),
                Html::e($profile->abonneeNummer),
                Html::e($profile->rolCode ?? 'none'),
            );
        }

        return Html::page('Choose a profile', sprintf(
            '<p>%s has more than one profile. DEZI asks which one to use.</p>'
            . '<form method="post" action="/authorize/profile"><input type="hidden" name="request_id" value="%s">'
            . '<fieldset><legend>Profile</legend>%s</fieldset>'
            . '<button name="action" value="continue">Continue</button> '
            . '<button name="action" value="cancel" formnovalidate>Cancel</button></form>',
            Html::e($person->displayName()),
            Html::e($authorization->id),
            $options,
        ));
    }

    private function complete(AuthorizationRequest $authorization, Person $person, Profile $profile): Response
    {
        $configuration = $this->loader->load();
        $now = $this->clock->now()->getTimestamp();
        $scenario = $authorization->scenario;
        $code = Jose::randomToken();
        $consumed = $this->store->transaction(static function (State $state) use (
            $authorization,
            $person,
            $profile,
            $scenario,
            $code,
            $now,
            $configuration,
        ): bool {
            if (!isset($state->authorizationRequests[$authorization->id])) {
                return false;
            }
            unset($state->authorizationRequests[$authorization->id]);
            if (!in_array($scenario, [Scenario::Cancel, Scenario::AuthorizeError], true)) {
                $state->codes[self::hash($code)] = new AuthorizationCode(
                    clientId: $authorization->clientId,
                    redirectUri: $authorization->redirectUri,
                    codeChallenge: $authorization->codeChallenge,
                    nonce: $authorization->nonce,
                    personId: $person->id,
                    profileId: $profile->id,
                    authTime: $authorization->authTime ?? $now,
                    attemptReceivedAt: $authorization->receivedAt,
                    scenario: $scenario,
                    expiresAt: $now + $configuration->codeSeconds,
                );
            }

            return true;
        });
        if (!$consumed) {
            return Html::error('This login has already been completed. Start again at the client.');
        }

        return match ($scenario) {
            Scenario::Cancel => self::errorRedirect($authorization, 'access_denied', 'The user cancelled at DEZI'),
            Scenario::AuthorizeError => self::errorRedirect($authorization, 'server_error', 'Mock DEZI error'),
            default => Responses::redirectTo($authorization->redirectUri, [
                'code' => $code,
                'state' => $scenario === Scenario::CallbackWrongState ? Jose::randomToken() : $authorization->state,
            ]),
        };
    }

    private function cancel(AuthorizationRequest $authorization): Response
    {
        $this->store->transaction(static function (State $state) use ($authorization): void {
            unset($state->authorizationRequests[$authorization->id]);
        });

        return self::errorRedirect($authorization, 'access_denied', 'The user cancelled at DEZI');
    }

    /**
     * PROVISIONAL: DEZI's error codes for a cancel or a failure are not known; these are RFC 6749 codes.
     */
    private static function errorRedirect(
        AuthorizationRequest $authorization,
        string $error,
        string $description,
    ): Response {
        return Responses::redirectTo($authorization->redirectUri, [
            'error' => $error,
            'error_description' => $description,
            'state' => $authorization->state,
        ]);
    }

    private function pendingRequest(Request $request): ?AuthorizationRequest
    {
        $id = $request->request->getString('request_id');

        return $this->store->transaction(
            static fn (State $state): ?AuthorizationRequest => $state->authorizationRequests[$id] ?? null,
        );
    }

    private function loginPage(AuthorizationRequest $authorization): Response
    {
        $default = $this->store->transaction(static fn (State $state): Scenario => $state->defaultScenario);
        $persons = '';
        foreach ($this->fixtures->persons() as $person) {
            $persons .= sprintf(
                '<label><input type="radio" name="person" value="%s" required> <strong>%s</strong>, DEZI number %s, '
                . '%d profile(s): %s</label>',
                Html::e($person->id),
                Html::e($person->displayName()),
                Html::e($person->deziNummer),
                count($person->profiles),
                Html::e($person->description),
            );
        }
        $groups = [];
        foreach (Scenario::cases() as $scenario) {
            $groups[$scenario->step()][] = sprintf(
                '<option value="%s"%s>%s: %s</option>',
                Html::e($scenario->value),
                $scenario === $default ? ' selected' : '',
                Html::e($scenario->value),
                Html::e($scenario->description()),
            );
        }
        $options = '';
        foreach ($groups as $step => $items) {
            $options .= sprintf('<optgroup label="%s">%s</optgroup>', Html::e($step), implode('', $items));
        }

        return Html::page('Log in (simulated eIDAS high)', sprintf(
            '<p>Client <code>%s</code> asks for a DEZI login. Choose a synthetic person and a scenario.</p>'
            . '<form method="post" action="/authorize/login"><input type="hidden" name="request_id" value="%s">'
            . '<fieldset><legend>Person</legend>%s</fieldset>'
            . '<fieldset><legend>Scenario for this login</legend><select name="scenario">%s</select></fieldset>'
            . '<button name="action" value="login">Log in</button> '
            . '<button name="action" value="cancel" formnovalidate>Cancel</button></form>',
            Html::e($authorization->clientId),
            Html::e($authorization->id),
            $persons,
            $options,
        ));
    }

    /**
     * @return array{string, string}|null the OAuth error code and description
     */
    private function requestError(Request $request): ?array
    {
        $query = $request->query;
        $scopes = self::words($query->getString('scope'));
        $prompts = self::words($query->getString('prompt'));
        $maxAge = $query->getString('max_age');
        $invalid = 'invalid_request';

        return match (true) {
            $query->has('request') || $query->has('request_uri')
                => ['request_not_supported', 'request objects are not supported'],
            $query->getString('response_type') !== 'code' => ['unsupported_response_type', 'only response_type=code'],
            $query->getString('response_mode', 'query') !== 'query' => [$invalid, 'only response_mode=query'],
            !in_array('openid', $scopes, true) => ['invalid_scope', 'scope must include openid'],
            array_diff($scopes, ['openid']) !== [] => ['invalid_scope', 'only scope openid is supported'],
            $query->getString('state') === '' => [$invalid, 'state is required by the mock'],
            $query->getString('nonce') === '' => [$invalid, 'nonce is required by the mock'],
            $query->getString('code_challenge_method') !== 'S256'
                => [$invalid, 'PKCE with code_challenge_method=S256 is required'],
            preg_match('/^[A-Za-z0-9_-]{43}$/', $query->getString('code_challenge')) !== 1
                => [$invalid, 'code_challenge must be a base64url SHA-256 value'],
            array_diff($prompts, self::SUPPORTED_PROMPTS) !== [] => [$invalid, 'unsupported prompt value'],
            in_array('none', $prompts, true) && count($prompts) > 1 => [$invalid, 'prompt=none cannot be combined'],
            $query->has('max_age') && preg_match('/^\d{1,9}$/', $maxAge) !== 1
                => [$invalid, 'max_age must be a non-negative integer'],
            default => null,
        };
    }

    private static function hash(string $value): string
    {
        return hash('sha256', $value);
    }

    /**
     * @return list<string>
     */
    private static function words(string $value): array
    {
        return array_values(array_filter(explode(' ', $value), static fn (string $word): bool => $word !== ''));
    }
}
