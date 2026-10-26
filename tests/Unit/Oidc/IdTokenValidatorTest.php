<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Oidc;

use DateTimeImmutable;
use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Oidc\IdToken\IdTokenClaims;
use JointIdentityProvider\Oidc\OidcFailure;
use JointIdentityProvider\Oidc\OidcFailureType;
use JointIdentityProvider\Tests\Support\OidcFixture;
use JointIdentityProvider\Tests\Support\TestProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * ID-token validation (design §14 "ID token", §18 "Messages" and "Keys").
 */
final class IdTokenValidatorTest extends TestCase
{
    private const string NONCE = 'stored-nonce';

    private OidcFixture $oidc;
    private JipConfiguration $configuration;
    private DateTimeImmutable $attemptStart;

    protected function setUp(): void
    {
        $this->oidc = new OidcFixture();
        $this->configuration = $this->oidc->configuration();
        $this->attemptStart = $this->oidc->clock->now();
        $this->oidc->clock->sleep(5);
    }

    protected function tearDown(): void
    {
        $this->oidc->remove();
    }

    public function test_a_valid_id_token_passes(): void
    {
        $claims = $this->validate(self::sign([], $this->now()));

        self::assertSame('pairwise-subject', $claims->subject);
        self::assertSame($this->now(), $claims->authTime);
    }

    /**
     * @param array<string, mixed> $claims
     */
    #[DataProvider('invalidClaims')]
    public function test_invalid_claims_are_refused(array $claims, string $detail): void
    {
        $this->assertRefused(self::sign($claims, $this->now()), OidcFailureType::IdTokenInvalid, $detail);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidClaims(): iterable
    {
        yield 'wrong issuer' => [['iss' => 'https://other.example'], 'iss differs'];
        yield 'issuer with a trailing slash' => [['iss' => TestProvider::ISSUER . '/'], 'iss differs'];
        yield 'wrong audience' => [['aud' => 'other-client'], 'aud is not exactly the client ID'];
        yield 'an extra audience' => [['aud' => [TestProvider::CLIENT_ID, 'other']], 'aud is not exactly the client ID'];
        yield 'an empty audience list' => [['aud' => []], 'aud is not exactly the client ID'];
        yield 'another authorised party' => [['azp' => 'other-client'], 'azp is not the client ID'];
        yield 'no subject' => [['sub' => null], 'sub is missing'];
        yield 'an empty subject' => [['sub' => ''], 'sub is missing'];
        yield 'wrong nonce' => [['nonce' => 'other'], 'nonce differs'];
        yield 'no nonce' => [['nonce' => null], 'nonce differs'];
        yield 'no auth_time' => [['auth_time' => null], 'auth_time is missing'];
        yield 'auth_time as a string' => [['auth_time' => '1791367200'], 'auth_time is missing'];
        yield 'no iat' => [['iat' => null], 'iat is missing'];
        yield 'no exp' => [['exp' => null], 'exp is missing'];
    }

    public function test_an_audience_list_with_only_the_client_passes(): void
    {
        $this->validate(self::sign(['aud' => [TestProvider::CLIENT_ID], 'azp' => TestProvider::CLIENT_ID], $this->now()));
        $this->expectNotToPerformAssertions();
    }

    public function test_time_limits_include_the_clock_skew(): void
    {
        $now = $this->now();
        $start = $this->attemptStart->getTimestamp();

        $this->validate(self::sign(['exp' => $now - 59, 'auth_time' => $start - 60, 'iat' => $now + 60], $now));
        $this->assertRefused(self::sign(['exp' => $now - 60], $now), OidcFailureType::IdTokenInvalid, 'exp has passed');
        $this->assertRefused(self::sign(['iat' => $now + 61], $now), OidcFailureType::IdTokenInvalid, 'iat lies in the future');
        $this->assertRefused(self::sign(['nbf' => $now + 61], $now), OidcFailureType::IdTokenInvalid, 'nbf lies in the future');
    }

    public function test_an_auth_time_from_before_the_attempt_is_refused(): void
    {
        $stale = $this->attemptStart->getTimestamp() - 61;

        $this->assertRefused(
            self::sign(['auth_time' => $stale], $this->now()),
            OidcFailureType::IdTokenInvalid,
            'auth_time lies before the attempt start',
        );
    }

    public function test_an_auth_time_in_the_future_is_refused(): void
    {
        $this->assertRefused(
            self::sign(['auth_time' => $this->now() + 61], $this->now()),
            OidcFailureType::IdTokenInvalid,
            'auth_time lies in the future',
        );
    }

    public function test_the_discovery_issuer_is_refused_when_the_expected_issuer_differs(): void
    {
        $this->configuration = $this->oidc->configuration([
            [['provider', 'expected_issuers', 'id_token'], 'https://auth.dezi.example'],
        ]);

        $this->assertRefused(self::sign([], $this->now()), OidcFailureType::IdTokenInvalid, 'iss differs');
        $this->validate(self::sign(['iss' => 'https://auth.dezi.example'], $this->now()));
    }

    /**
     * @param array<string, mixed> $header
     */
    #[DataProvider('invalidHeaders')]
    public function test_invalid_headers_are_refused_before_any_key_fetch(array $header, string $detail): void
    {
        $token = TestProvider::sign($header, self::claims($this->now()));

        $this->assertRefused($token, OidcFailureType::IdTokenInvalid, $detail);
        self::assertSame(0, $this->oidc->provider->countRequests([TestProvider::ID_TOKEN_JWKS]));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidHeaders(): iterable
    {
        yield 'alg none' => [['alg' => 'none', 'kid' => TestProvider::KID], 'alg is not RS256'];
        yield 'alg HS256' => [['alg' => 'HS256', 'kid' => TestProvider::KID], 'alg is not RS256'];
        yield 'alg RS512' => [['alg' => 'RS512', 'kid' => TestProvider::KID], 'alg is not RS256'];
        yield 'no kid' => [['alg' => 'RS256'], 'no kid'];
        yield 'crit' => [['alg' => 'RS256', 'kid' => TestProvider::KID, 'crit' => ['exp']], 'unsupported header'];
        yield 'jku elsewhere' => [
            ['alg' => 'RS256', 'kid' => TestProvider::KID, 'jku' => TestProvider::STATEMENT_JWKS],
            'jku is not the approved key address',
        ];
    }

    public function test_a_jku_equal_to_the_approved_address_is_accepted(): void
    {
        $token = TestProvider::sign(
            ['alg' => 'RS256', 'kid' => TestProvider::KID, 'jku' => TestProvider::ID_TOKEN_JWKS],
            self::claims($this->now()),
        );

        $this->validate($token);
        $this->expectNotToPerformAssertions();
    }

    public function test_a_signature_from_another_key_under_the_published_kid_is_refused(): void
    {
        $token = TestProvider::sign(['alg' => 'RS256', 'kid' => TestProvider::KID], self::claims($this->now()), 'other-key');

        $this->assertRefused($token, OidcFailureType::IdTokenInvalid, 'signature is invalid');
    }

    public function test_a_tampered_payload_is_refused(): void
    {
        [$header, , $signature] = explode('.', self::sign([], $this->now()));
        $payload = TestProvider::b64((string) json_encode(self::claims($this->now()) + ['extra' => true]));

        $this->assertRefused($header . '.' . $payload . '.' . $signature, OidcFailureType::IdTokenInvalid, 'signature is invalid');
    }

    public function test_a_key_published_only_at_another_address_is_refused(): void
    {
        $this->oidc->provider->answers[TestProvider::STATEMENT_JWKS] = static fn (): mixed => TestProvider::json([
            'keys' => [TestProvider::publicJwk('statement-key', 'statement-key')],
        ]);
        $token = TestProvider::sign(['alg' => 'RS256', 'kid' => 'statement-key'], self::claims($this->now()), 'statement-key');

        $this->assertRefused($token, OidcFailureType::UnknownKey, 'id_token: kid not in the approved key set');
        self::assertSame(0, $this->oidc->provider->countRequests([TestProvider::STATEMENT_JWKS]));
    }

    public function test_not_a_compact_jws_is_refused(): void
    {
        $this->assertRefused('a.b', OidcFailureType::IdTokenInvalid, 'not a compact JWS');
        $this->assertRefused('a.b.c.d.e', OidcFailureType::IdTokenInvalid, 'not a compact JWS');
    }

    private function validate(string $token): IdTokenClaims
    {
        return $this->oidc->idTokens()->validate(
            $token,
            $this->configuration->provider,
            $this->configuration->provider->oidc->clients['ggd'],
            self::NONCE,
            $this->attemptStart,
        );
    }

    private function assertRefused(string $token, OidcFailureType $type, string $detail): void
    {
        try {
            $this->validate($token);
            self::fail('The ID token was accepted.');
        } catch (OidcFailure $failure) {
            self::assertSame($type, $failure->type);
            self::assertStringContainsString($detail, $failure->detail);
        }
    }

    private function now(): int
    {
        return $this->oidc->clock->now()->getTimestamp();
    }

    /**
     * @param array<string, mixed> $changes
     */
    private static function sign(array $changes, int $now): string
    {
        return TestProvider::sign(['alg' => 'RS256', 'kid' => TestProvider::KID], self::claims($now, $changes));
    }

    /**
     * @param array<string, mixed> $changes
     * @return array<string, mixed>
     */
    private static function claims(int $now, array $changes = []): array
    {
        $claims = [
            'iss' => TestProvider::ISSUER,
            'sub' => 'pairwise-subject',
            'aud' => TestProvider::CLIENT_ID,
            'iat' => $now,
            'exp' => $now + 300,
            'auth_time' => $now,
            'nonce' => self::NONCE,
        ];
        foreach ($changes as $name => $value) {
            if ($value === null) {
                unset($claims[$name]);
            } else {
                $claims[$name] = $value;
            }
        }

        return $claims;
    }
}
