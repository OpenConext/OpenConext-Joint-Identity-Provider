<?php

declare(strict_types=1);

namespace JointIdentityProvider\TestSp;

use Exception;
use InvalidArgumentException;
use OneLogin\Saml2\Auth;
use Throwable;

/**
 * The test SP's routes. EngineBlock is its only IdP; the access decision follows design §7.
 */
final readonly class Application
{
    private const string SESSION_COOKIE = 'jip_test_sp';
    private const string PENDING_REQUEST = 'pending_request_id';
    private const string RESULT = 'result';

    public function __construct(private Configuration $configuration)
    {
    }

    public function handle(string $method, string $path): void
    {
        match ([$method, $path]) {
            ['GET', '/health'] => self::text(200, 'UP'),
            ['GET', '/'] => $this->home(),
            ['GET', '/login'] => $this->login(),
            ['POST', '/saml/acs'] => $this->acs(),
            ['GET', '/saml/metadata'] => $this->metadata(),
            ['POST', '/logout'] => $this->logout(),
            default => self::text(404, 'Not found'),
        };
    }

    private function home(): void
    {
        $this->startSession();
        $result = $_SESSION[self::RESULT] ?? null;
        if (!is_array($result)) {
            Page::send(200, 'Not logged in', '<p>This service makes the access decision of design §7 on the'
                . ' attributes that EngineBlock and JIP release.</p><p><a href="/login">Log in through'
                . ' EngineBlock</a></p>');

            return;
        }

        $access = Access::tryFrom(self::stringOf($result, 'access')) ?? Access::Refused;
        $attributes = self::attributesOf($result);
        $prefix = $this->configuration->rules->reservedPrefix;
        $dezi = array_filter(
            $attributes,
            static fn (string $name): bool => str_starts_with($name, $prefix),
            ARRAY_FILTER_USE_KEY,
        );
        $organisation = array_diff_key($attributes, $dezi);

        Page::send(200, $access->label(), sprintf(
            '<p class="%s"><strong>%s</strong>: %s</p>'
            . '<p>SP request ID (EngineBlock request ID in JIP\'s log): <code>%s</code><br>'
            . 'Response ID: <code>%s</code></p>'
            . '<h2>Attributes under the reserved DEZI names</h2>%s'
            . '<h2>Organisation attributes</h2>%s'
            . '<p><a href="/login">Log in again</a> '
            . '<form method="post" action="/logout"><button type="submit">Log out</button></form></p>',
            Page::e($access->value),
            Page::e($access->label()),
            Page::e(self::stringOf($result, 'reason')),
            Page::e(self::stringOf($result, 'request_id')),
            Page::e(self::stringOf($result, 'response_id')),
            Page::attributeTable($dezi),
            Page::attributeTable($organisation),
        ));
    }

    private function login(): void
    {
        $this->startSession();
        $auth = new Auth($this->configuration->saml);
        $url = $auth->login(null, [], false, false, true);
        $requestId = $auth->getLastRequestID();
        $_SESSION[self::PENDING_REQUEST] = $requestId;
        unset($_SESSION[self::RESULT]);
        Log::info(sprintf('login request %s sent to EngineBlock', Log::samlId($requestId)));

        header('Cache-Control: no-store');
        header('Location: ' . $url, true, 302);
    }

    private function acs(): void
    {
        $this->startSession();
        $requestId = $_SESSION[self::PENDING_REQUEST] ?? null;
        unset($_SESSION[self::PENDING_REQUEST]);
        if (!is_string($requestId)) {
            Log::info('response refused: no login request pending in this session');
            Page::send(400, 'Response not accepted', '<p>No login is pending in this browser session.</p>'
                . '<p><a href="/login">Log in again</a></p>');

            return;
        }

        $auth = new Auth($this->configuration->saml);
        try {
            $auth->processResponse($requestId);
        } catch (Exception $exception) {
            Log::info(sprintf('response for request %s refused (%s)', Log::samlId($requestId), $exception::class));
            Page::send(400, 'Response not accepted', '<p>The SAML response could not be processed.</p>'
                . '<p><a href="/login">Log in again</a></p>');

            return;
        }
        // Error codes only: the reason text can quote message content.
        if ($auth->getErrors() !== [] || !$auth->isAuthenticated()) {
            Log::info(sprintf(
                'response for request %s refused (%s)',
                Log::samlId($requestId),
                implode(', ', array_filter($auth->getErrors(), is_string(...))),
            ));
            Page::send(403, 'Response not accepted', '<p>The SAML response failed validation.</p>'
                . '<p><a href="/login">Log in again</a></p>');

            return;
        }

        $attributes = self::normalise($auth->getAttributes());
        $decision = (new AccessDecision($this->configuration->rules))->decide($attributes);
        $responseId = $auth->getLastMessageId();
        Log::info(sprintf(
            'request %s, response %s, assertion %s: %s (%s)',
            Log::samlId($requestId),
            Log::samlId($responseId),
            Log::samlId($auth->getLastAssertionId()),
            $decision->access->value,
            $decision->reason,
        ));

        session_regenerate_id(true);
        $_SESSION[self::RESULT] = [
            'access' => $decision->access->value,
            'reason' => $decision->reason,
            'request_id' => $requestId,
            'response_id' => $responseId,
            'attributes' => $attributes,
        ];

        header('Cache-Control: no-store');
        header('Location: /', true, 303);
    }

    private function metadata(): void
    {
        $auth = new Auth($this->configuration->saml);
        header('Content-Type: application/samlmetadata+xml');
        echo $auth->getSettings()->getSPMetadata();
    }

    private function logout(): void
    {
        $this->startSession();
        $_SESSION = [];
        session_destroy();
        setcookie(self::SESSION_COOKIE, '', [
            'expires' => 1,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        header('Location: /', true, 303);
    }

    private function startSession(): void
    {
        session_name(self::SESSION_COOKIE);
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            // EngineBlock's POST to the ACS is same-site (*.dev.openconext.local), so Lax carries the cookie.
            'samesite' => 'Lax',
        ]);
        session_start([
            'use_strict_mode' => true,
            'use_only_cookies' => true,
            'use_trans_sid' => false,
        ]);
    }

    /**
     * @param array<mixed> $attributes
     * @return array<string, list<string>>
     */
    private static function normalise(array $attributes): array
    {
        $result = [];
        foreach ($attributes as $name => $values) {
            if (!is_string($name) || !is_array($values)) {
                continue;
            }
            $result[$name] = array_values(array_map(
                static fn (mixed $v): string => is_scalar($v) ? (string) $v : '',
                $values,
            ));
        }

        return $result;
    }

    /**
     * @param array<mixed> $result
     * @return array<string, list<string>>
     */
    private static function attributesOf(array $result): array
    {
        $attributes = $result['attributes'] ?? [];

        return is_array($attributes) ? self::normalise($attributes) : [];
    }

    /**
     * @param array<mixed> $result
     */
    private static function stringOf(array $result, string $key): string
    {
        $value = $result[$key] ?? '';

        return is_string($value) ? $value : '';
    }

    private static function text(int $status, string $text): void
    {
        http_response_code($status);
        header('Content-Type: text/plain; charset=UTF-8');
        header('Cache-Control: no-store');
        echo $text;
    }

    public static function configurationFailure(InvalidArgumentException $exception): void
    {
        // Called only for Configuration::load(): its validation messages contain setting names, not values.
        Log::info(sprintf('configuration error: %s', $exception->getMessage()));
        self::text(500, 'Internal error');
    }

    public static function failSafe(Throwable $exception): void
    {
        Log::info(sprintf(
            'internal error (%s) at %s:%d',
            $exception::class,
            basename($exception->getFile()),
            $exception->getLine(),
        ));
        self::text(500, 'Internal error');
    }
}
