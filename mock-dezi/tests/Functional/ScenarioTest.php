<?php

declare(strict_types=1);

namespace MockDezi\Tests\Functional;

use MockDezi\Scenario\Scenario;
use MockDezi\Tests\Support\JipSimulator;
use MockDezi\Tests\Support\MockDeziTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Every login scenario changes exactly what it describes; all other parts of the login stay valid.
 */
final class ScenarioTest extends MockDeziTestCase
{
    private const string ID_TOKEN_KEYS = '/openid/connect/jwks.json';
    private const string ENVELOPE_KEYS = '/envelope/jwks.json';
    private const string STATEMENT_KEYS = '/dezi/jwks.json';

    /**
     * @return iterable<string, array{Scenario}>
     */
    public static function scenarios(): iterable
    {
        foreach (Scenario::cases() as $scenario) {
            yield $scenario->value => [$scenario];
        }
    }

    #[DataProvider('scenarios')]
    public function test_the_scenario_has_its_described_effect(Scenario $scenario): void
    {
        $requestId = JipSimulator::requestId($this->jip->authorize());
        $callbackResponse = $this->jip->login($requestId, 'anna', $scenario->value);
        $callback = JipSimulator::callback($callbackResponse);

        if ($scenario->step() === 'authorisation response') {
            $this->assertCallback($scenario, $callback);

            return;
        }
        self::assertSame($this->jip->state, $callback['state']);
        $tokenResponse = $this->jip->token($callback['code']);
        if ($scenario->step() === 'token response') {
            $this->assertTokenResponse($scenario, $tokenResponse);

            return;
        }
        self::assertSame(200, $tokenResponse->getStatusCode());
        $tokens = JipSimulator::json($tokenResponse);
        self::assertIsString($tokens['id_token']);
        self::assertIsString($tokens['access_token']);
        if ($scenario->step() === 'ID token') {
            $this->assertIdToken($scenario, $tokens['id_token']);

            return;
        }
        $this->assertValidIdToken($tokens['id_token']);

        $userInfo = $this->jip->userinfo($tokens['access_token']);
        if ($scenario->step() === 'UserInfo (JWE)') {
            $this->assertUserInfo($scenario, $userInfo);

            return;
        }
        $envelope = $this->jip->decrypt((string) $userInfo->getContent());
        if ($scenario->step() === 'envelope') {
            $this->assertEnvelope($scenario, $envelope);

            return;
        }
        $envelopeClaims = JipSimulator::verify($envelope, $this->jip->keySet(self::ENVELOPE_KEYS));
        self::assertNotNull($envelopeClaims);
        self::assertIsString($envelopeClaims['verklaring']);
        if ($scenario->step() === 'statement') {
            $this->assertStatement($scenario, $envelopeClaims['verklaring'], $envelopeClaims);

            return;
        }
        $statement = JipSimulator::verify($envelopeClaims['verklaring'], $this->jip->keySet(self::STATEMENT_KEYS));
        self::assertNotNull($statement);
        self::assertSame($envelopeClaims['verklaring_id'], $statement['verklaring_id']);

        self::assertIsString($statement['verklaring_id']);
        $this->assertStatus($scenario, $statement['verklaring_id']);
    }

    /**
     * @param array<string, string> $callback
     */
    private function assertCallback(Scenario $scenario, array $callback): void
    {
        match ($scenario) {
            Scenario::Cancel => self::assertSame(['access_denied', $this->jip->state], [$callback['error'], $callback['state']]),
            Scenario::AuthorizeError => self::assertSame('server_error', $callback['error']),
            Scenario::CallbackWrongState => self::assertNotSame($this->jip->state, $callback['state']),
            Scenario::StaleAuthTime, Scenario::FutureAuthTime => $this->assertAuthTime($scenario, $callback['code']),
            default => self::fail('no expectation for ' . $scenario->value),
        };
        if (in_array($scenario, [Scenario::Cancel, Scenario::AuthorizeError], true)) {
            self::assertArrayNotHasKey('code', $callback);
        }
    }

    private function assertAuthTime(Scenario $scenario, string $code): void
    {
        $tokens = JipSimulator::json($this->jip->token($code));
        self::assertIsString($tokens['id_token']);
        $claims = JipSimulator::verify($tokens['id_token'], $this->jip->keySet(self::ID_TOKEN_KEYS));
        self::assertNotNull($claims);
        self::assertIsInt($claims['auth_time']);
        if ($scenario === Scenario::StaleAuthTime) {
            self::assertLessThan($this->jip->attemptStart - 800, $claims['auth_time']);
        } else {
            self::assertGreaterThan(time() + 500, $claims['auth_time']);
        }
    }

    private function assertTokenResponse(Scenario $scenario, Response $response): void
    {
        $body = JipSimulator::json($response);
        match ($scenario) {
            Scenario::TokenServerError => self::assertSame(500, $response->getStatusCode()),
            Scenario::TokenInvalidClient => self::assertSame([401, 'invalid_client'], [$response->getStatusCode(), $body['error']]),
            Scenario::TokenInvalidGrant => self::assertSame([400, 'invalid_grant'], [$response->getStatusCode(), $body['error']]),
            Scenario::TokenTypeNotBearer => self::assertSame('N_A', $body['token_type']),
            Scenario::TokenWithoutIdToken => self::assertArrayNotHasKey('id_token', $body),
            Scenario::TokenWithoutAccessToken => self::assertArrayNotHasKey('access_token', $body),
            default => self::fail('no expectation for ' . $scenario->value),
        };
    }

    private function assertIdToken(Scenario $scenario, string $idToken): void
    {
        $keys = $this->jip->keySet(self::ID_TOKEN_KEYS);
        $claims = JipSimulator::payload($idToken);
        $verified = JipSimulator::verify($idToken, $keys);
        if (in_array($scenario, [Scenario::IdTokenWrongIssuer, Scenario::IdTokenWrongNonce], true)) {
            self::assertNotNull($verified);
        }
        match ($scenario) {
            Scenario::IdTokenBadSignature, Scenario::IdTokenUnknownKid => self::assertNull($verified),
            Scenario::IdTokenSignedWithStatementKey => self::assertSame(
                [false, true],
                [$verified !== null, JipSimulator::verify($idToken, $this->jip->keySet(self::STATEMENT_KEYS)) !== null],
            ),
            Scenario::IdTokenAlgNone => self::assertSame(['none', null], [JipSimulator::header($idToken)['alg'], $verified]),
            Scenario::IdTokenWrongIssuer => self::assertNotSame(JipSimulator::ISSUER, $verified['iss'] ?? null),
            Scenario::IdTokenWrongAudience => self::assertSame('another-client', $verified['aud'] ?? null),
            Scenario::IdTokenExtraAudience => self::assertSame(
                [$this->jip->clientId, 'untrusted-audience'],
                $verified['aud'] ?? null,
            ),
            Scenario::IdTokenWrongNonce => self::assertNotSame($this->jip->nonce, $verified['nonce'] ?? null),
            Scenario::IdTokenExpired => self::assertLessThan(time(), $verified['exp'] ?? PHP_INT_MAX),
            Scenario::IdTokenWithoutAuthTime => self::assertSame([true, false], [
                $verified !== null,
                array_key_exists('auth_time', $claims),
            ]),
            Scenario::IdTokenWithoutSub => self::assertSame([true, false], [
                $verified !== null,
                array_key_exists('sub', $claims),
            ]),
            default => self::fail('no expectation for ' . $scenario->value),
        };
    }

    private function assertValidIdToken(string $idToken): void
    {
        $claims = JipSimulator::verify($idToken, $this->jip->keySet(self::ID_TOKEN_KEYS));
        self::assertNotNull($claims);
        self::assertSame([JipSimulator::ISSUER, $this->jip->clientId, $this->jip->nonce], [
            $claims['iss'],
            $claims['aud'],
            $claims['nonce'],
        ]);
    }

    private function assertUserInfo(Scenario $scenario, Response $response): void
    {
        if ($scenario === Scenario::UserInfoServerError) {
            self::assertSame(500, $response->getStatusCode());

            return;
        }
        $body = (string) $response->getContent();
        $header = JipSimulator::header($body);
        match ($scenario) {
            Scenario::UserInfoNotEncrypted => self::assertSame(['RS256', 3], [$header['alg'], count(explode('.', $body))]),
            Scenario::UserInfoWrongKeyAlgorithm => self::assertSame(['RSA-OAEP-256', 'A256CBC-HS512'], [$header['alg'], $header['enc']]),
            Scenario::UserInfoWrongContentEncryption => self::assertSame(['RSA-OAEP', 'A256GCM'], [$header['alg'], $header['enc']]),
            Scenario::UserInfoUnregisteredKey => self::assertSame(
                ['RSA-OAEP', 'A256CBC-HS512', 5, false],
                [$header['alg'], $header['enc'], count(explode('.', $body)), $this->decrypts($body)],
            ),
            Scenario::UserInfoUnknownKid => self::assertSame([true, 'mock-dezi-unknown-encryption-kid'], [
                $this->decrypts($body),
                $header['kid'],
            ]),
            default => self::fail('no expectation for ' . $scenario->value),
        };
    }

    private function assertEnvelope(Scenario $scenario, string $envelope): void
    {
        $verified = JipSimulator::verify($envelope, $this->jip->keySet(self::ENVELOPE_KEYS));
        if ($scenario === Scenario::EnvelopeWrongIssuer) {
            self::assertNotNull($verified);
        }
        $byIdTokenKey = JipSimulator::verify($envelope, $this->jip->keySet(self::ID_TOKEN_KEYS));
        $header = JipSimulator::header($envelope);
        $claims = JipSimulator::payload($envelope);
        match ($scenario) {
            Scenario::EnvelopeBadSignature, Scenario::EnvelopeUnknownKid => self::assertSame([null, null], [$verified, $byIdTokenKey]),
            Scenario::EnvelopeSignedWithIdTokenKey => self::assertSame([false, true, false], [
                $verified !== null,
                $byIdTokenKey !== null,
                isset($header['jku']),
            ]),
            Scenario::EnvelopeJkuOtherAddress => self::assertSame(
                [false, true, JipSimulator::ISSUER . self::ID_TOKEN_KEYS],
                [$verified !== null, $byIdTokenKey !== null, $header['jku'] ?? null],
            ),
            Scenario::EnvelopeWrongIssuer => self::assertNotSame('auth.mock-dezi.dev.openconext.local', $verified['iss'] ?? null),
            Scenario::EnvelopeWrongAudience => self::assertSame('another-audience', $verified['aud'] ?? null),
            Scenario::EnvelopeExpired => self::assertLessThan(time(), $verified['exp'] ?? PHP_INT_MAX),
            Scenario::EnvelopeWrongLoa => self::assertSame('http://eidas.europa.eu/LoA/substantial', $verified['loa_authn'] ?? null),
            Scenario::EnvelopeWithoutVerklaringId => self::assertSame([true, false], [
                $verified !== null,
                array_key_exists('verklaring_id', $claims),
            ]),
            Scenario::EnvelopeWithSub, Scenario::EnvelopeSubMismatch => $this->assertEnvelopeSub($scenario, $verified),
            default => self::fail('no expectation for ' . $scenario->value),
        };
    }

    /**
     * @param array<string, mixed>|null $envelope
     */
    private function assertEnvelopeSub(Scenario $scenario, ?array $envelope): void
    {
        self::assertNotNull($envelope);
        self::assertIsString($envelope['sub']);
        $tokens = (new JipSimulator($this->browser, $this->fixture))->tokens('anna');
        self::assertIsString($tokens['id_token']);
        $sub = JipSimulator::payload($tokens['id_token'])['sub'];
        $scenario === Scenario::EnvelopeWithSub
            ? self::assertSame($sub, $envelope['sub'])
            : self::assertNotSame($sub, $envelope['sub']);
    }

    /**
     * @param array<string, mixed> $envelope
     */
    private function assertStatement(Scenario $scenario, string $statement, array $envelope): void
    {
        $verified = JipSimulator::verify($statement, $this->jip->keySet(self::STATEMENT_KEYS));
        if (in_array($scenario, [Scenario::StatementWrongIssuer, Scenario::StatementVerklaringIdMismatch], true)) {
            self::assertNotNull($verified);
        }
        $byIdTokenKey = JipSimulator::verify($statement, $this->jip->keySet(self::ID_TOKEN_KEYS));
        $header = JipSimulator::header($statement);
        match ($scenario) {
            Scenario::StatementBadSignature, Scenario::StatementUnknownKid => self::assertSame([null, null], [$verified, $byIdTokenKey]),
            Scenario::StatementSignedWithIdTokenKey => self::assertSame(
                [false, true, JipSimulator::ISSUER . self::STATEMENT_KEYS],
                [$verified !== null, $byIdTokenKey !== null, $header['jku']],
            ),
            Scenario::StatementJkuOtherAddress => self::assertSame(
                [false, true, JipSimulator::ISSUER . self::ID_TOKEN_KEYS],
                [$verified !== null, $byIdTokenKey !== null, $header['jku']],
            ),
            Scenario::StatementWrongIssuer => self::assertNotSame('abonnee.mock-dezi.dev.openconext.local', $verified['iss'] ?? null),
            Scenario::StatementExpired => self::assertLessThan(time(), $verified['exp'] ?? PHP_INT_MAX),
            Scenario::StatementNotYetValid => self::assertGreaterThan(time(), $verified['nbf'] ?? 0),
            Scenario::StatementTimeAsString => self::assertMatchesRegularExpression('/^\d+$/', self::string($verified['exp'] ?? null)),
            Scenario::StatementVerklaringIdMismatch => self::assertNotSame($envelope['verklaring_id'], $verified['verklaring_id'] ?? null),
            Scenario::StatementVerklaringIdNotUuid => self::assertSame(
                [$envelope['verklaring_id'], 0],
                [$verified['verklaring_id'] ?? null, preg_match('/^[0-9a-f-]{36}$/', self::string($envelope['verklaring_id']))],
            ),
            Scenario::StatementWrongLoa => self::assertSame('http://eidas.europa.eu/LoA/substantial', $verified['loa_dezi'] ?? null),
            Scenario::StatementNumericDeziNummer => self::assertSame(900000001, $verified['dezi_nummer'] ?? null),
            Scenario::StatementEmptyAbonneeNummer => self::assertSame('', $verified['abonnee_nummer'] ?? null),
            Scenario::StatementDeziNummerNull => self::assertSame([true, null], [
                $verified !== null && array_key_exists('dezi_nummer', $verified),
                $verified['dezi_nummer'] ?? null,
            ]),
            Scenario::StatementRolCodeNull => self::assertSame([true, null], [
                $verified !== null && array_key_exists('rol_code', $verified),
                $verified['rol_code'] ?? null,
            ]),
            Scenario::StatementVoorvoegselStringNull => self::assertSame('null', $verified['voorvoegsel'] ?? null),
            default => self::fail('no expectation for ' . $scenario->value),
        };
    }

    private function assertStatus(Scenario $scenario, string $verklaringId): void
    {
        if ($scenario === Scenario::Success) {
            self::assertSame('d3e2a1c0-0001-4000-8000-000000000001', $verklaringId);
        } else {
            self::assertNotSame('d3e2a1c0-0001-4000-8000-000000000001', $verklaringId, 'a fresh statement');
        }
        $this->browser->request('GET', '/status/v1/verklaring/' . $verklaringId);
        $response = $this->browser->getResponse();
        $body = json_decode((string) $response->getContent(), true);
        $status = is_array($body) ? $body['status'] ?? null : null;
        match ($scenario) {
            Scenario::Success => self::assertSame([200, 'actief'], [$response->getStatusCode(), $status]),
            Scenario::StatusRevoked => self::assertSame([200, 'ingetrokken'], [$response->getStatusCode(), $status]),
            Scenario::StatusOtherStatus => self::assertSame([200, 'mock-andere-status'], [$response->getStatusCode(), $status]),
            Scenario::StatusNotFound => self::assertSame([404, 'application/problem+json'], [
                $response->getStatusCode(),
                $response->headers->get('Content-Type'),
            ]),
            Scenario::StatusBadRequest => self::assertSame(400, $response->getStatusCode()),
            Scenario::StatusServerError => self::assertSame(500, $response->getStatusCode()),
            Scenario::StatusTimeout => self::assertSame([200, 'actief'], [$response->getStatusCode(), $status]),
            Scenario::StatusRedirect => self::assertSame(
                [302, JipSimulator::ISSUER . '/status/v1/verklaring/' . $verklaringId . '?redirected=1'],
                [$response->getStatusCode(), $response->headers->get('Location')],
            ),
            Scenario::StatusInvalidBody => self::assertSame([200, null], [$response->getStatusCode(), $body]),
            Scenario::StatusWrongId => self::assertSame([200, 'actief', false], [
                $response->getStatusCode(),
                $status,
                is_array($body) && ($body['verklaringId'] ?? null) === $verklaringId,
            ]),
            default => self::fail('no expectation for ' . $scenario->value),
        };
    }

    private function decrypts(string $jwe): bool
    {
        try {
            $this->jip->decrypt($jwe);
        } catch (Throwable) {
            return false;
        }

        return true;
    }

    private static function string(mixed $value): string
    {
        self::assertIsString($value);

        return $value;
    }
}
