<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Profile\Dezi;

use Closure;
use DateTimeImmutable;
use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Core\Profile\ProfileOutcome;
use JointIdentityProvider\Core\Profile\ProfileResult;
use JointIdentityProvider\Oidc\AuthenticatedLogin;
use JointIdentityProvider\Oidc\Discovery\ProviderMetadata;
use JointIdentityProvider\Oidc\IdToken\IdTokenClaims;
use JointIdentityProvider\Profile\Dezi\DeziProfile;
use JointIdentityProvider\Tests\Support\OidcFixture;
use JointIdentityProvider\Tests\Support\TestProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * The DEZI profile end to end against the fake provider: envelope, statement, claim types, revocation
 * and the delivery-time recheck (design §14–§16, §18 "Messages", "Keys", "Revocation", "Profiles",
 * "Optional claims").
 */
final class DeziProfileTest extends TestCase
{
    private const string OTHER_UUID = 'd3e2a1c0-0002-4000-8000-000000000002';

    private OidcFixture $oidc;
    private TestProvider $provider;
    private int $now;

    protected function setUp(): void
    {
        $this->oidc = new OidcFixture();
        $this->provider = $this->oidc->provider;
        $this->now = $this->oidc->clock->now()->getTimestamp();
        $this->provider->now = $this->now;
        $this->provider->userInfoRecipient = $this->oidc->decryptionCertificate();
    }

    protected function tearDown(): void
    {
        $this->oidc->remove();
    }

    public function test_a_valid_login_yields_the_statement_claims_exactly_as_sent(): void
    {
        $result = $this->verified($this->validate());

        self::assertSame([
            'dezi_nummer' => ['900000001'],
            'abonnee_nummer' => ['90000001'],
            'rol_code' => ['01.000'],
            'rol_naam' => ['Arts'],
            'abonnee_naam' => ['Mock GGD Noord'],
            'voorletters' => ['A.'],
            'achternaam' => ['Mockarts'],
        ], $result->verifiedClaims());
        // The envelope's exp is earlier than the statement's.
        self::assertSame($this->now + 300, $result->hardExpiry()->getTimestamp());
        self::assertSame([
            DeziProfile::STATE_VERKLARING_ID => TestProvider::VERKLARING_ID,
            DeziProfile::STATE_DECISION_VALID_UNTIL => (int) $this->oidc->clock->now()->modify('+60 seconds')->format('Uu'),
        ], $result->recheckState());
    }

    public function test_the_hard_expiry_is_the_earlier_of_envelope_and_statement(): void
    {
        $this->provider->statementClaims = ['exp' => $this->now + 120];

        self::assertSame($this->now + 120, $this->verified($this->validate())->hardExpiry()->getTimestamp());
    }

    public function test_identifiers_keep_their_exact_format(): void
    {
        $this->provider->statementClaims = [
            'dezi_nummer' => '0900000001',
            'abonnee_nummer' => '00000001',
            'rol_code' => '1.015',
        ];

        $claims = $this->verified($this->validate())->verifiedClaims();

        self::assertSame(['0900000001'], $claims['dezi_nummer']);
        self::assertSame(['00000001'], $claims['abonnee_nummer']);
        self::assertSame(['1.015'], $claims['rol_code']);
    }

    public function test_role_code_00_000_is_kept_like_any_other_role_code(): void
    {
        $this->provider->statementClaims = ['rol_code' => '00.000', 'rol_naam' => TestProvider::ABSENT];

        self::assertSame(['00.000'], $this->verified($this->validate())->verifiedClaims()['rol_code'] ?? null);
    }

    public function test_a_profile_without_a_role_code_gives_no_role(): void
    {
        $this->provider->statementClaims = ['rol_code' => TestProvider::ABSENT, 'rol_naam' => TestProvider::ABSENT];

        $claims = $this->verified($this->validate())->verifiedClaims();

        self::assertArrayNotHasKey('rol_code', $claims);
        self::assertArrayNotHasKey('rol_naam', $claims);
    }

    public function test_a_permitted_null_becomes_absent(): void
    {
        $this->provider->statementClaims = ['voorvoegsel' => null];

        self::assertArrayNotHasKey('voorvoegsel', $this->verified($this->validate())->verifiedClaims());
    }

    public function test_a_null_that_the_configuration_does_not_permit_is_refused(): void
    {
        $this->provider->statementClaims = ['voorvoegsel' => null];

        $this->assertFailure(
            $this->validate([[['provider', 'statement', 'nullable_claims'], []]]),
            'statement_invalid',
        );
    }

    public function test_a_supplied_envelope_sub_equal_to_the_id_token_sub_passes(): void
    {
        $this->provider->envelopeClaims = ['sub' => TestProvider::SUBJECT];

        $this->verified($this->validate());
        $this->verified($this->validate([[['provider', 'envelope', 'subject_association'], 'envelope_sub']]));
    }

    public function test_envelope_sub_association_requires_an_envelope_sub(): void
    {
        $this->assertFailure(
            $this->validate([[['provider', 'envelope', 'subject_association'], 'envelope_sub']]),
            'envelope_invalid',
        );
    }

    /**
     * @param Closure(TestProvider): void $change
     */
    #[DataProvider('invalidEnvelopes')]
    public function test_an_invalid_envelope_is_refused(Closure $change, string $failureType): void
    {
        $change($this->provider);

        $this->assertFailure($this->validate(), $failureType);
    }

    /**
     * @return iterable<string, array{Closure(TestProvider): void, string}>
     */
    public static function invalidEnvelopes(): iterable
    {
        $claims = self::envelopeClaims(...);

        yield 'another issuer' => [$claims(['iss' => 'auth.dezi.nl']), 'envelope_invalid'];
        yield 'the client ID as audience' => [$claims(['aud' => TestProvider::CLIENT_ID]), 'envelope_invalid'];
        yield 'an extra audience' => [$claims(['aud' => [TestProvider::ENVELOPE_AUDIENCE, 'other']]), 'envelope_invalid'];
        yield 'no audience' => [$claims(['aud' => TestProvider::ABSENT]), 'envelope_invalid'];
        yield 'another subject' => [$claims(['sub' => 'other-subject']), 'envelope_invalid'];
        yield 'a non-string subject' => [$claims(['sub' => 42]), 'envelope_invalid'];
        yield 'the DEZI number as subject' => [$claims(['sub' => '900000001']), 'envelope_invalid'];
        yield 'loa_authn spelled like loa_dezi' => [$claims(['loa_authn' => TestProvider::LOA_DEZI]), 'envelope_invalid'];
        yield 'no loa_authn' => [$claims(['loa_authn' => TestProvider::ABSENT]), 'envelope_invalid'];
        yield 'no verklaring_id' => [$claims(['verklaring_id' => TestProvider::ABSENT]), 'envelope_invalid'];
        yield 'no statement' => [$claims(['verklaring' => TestProvider::ABSENT]), 'envelope_invalid'];
        yield 'iat as a string' => [$claims(['iat' => '1791367200']), 'envelope_invalid'];
        yield 'no exp' => [$claims(['exp' => TestProvider::ABSENT]), 'envelope_invalid'];
        yield 'exp passed' => [static function (TestProvider $p): void {
            $p->envelopeClaims = ['exp' => (int) $p->now];
        }, 'envelope_invalid'];
        yield 'iat beyond the clock skew' => [static function (TestProvider $p): void {
            $p->envelopeClaims = ['iat' => (int) $p->now + 61];
        }, 'envelope_invalid'];
        yield 'signed with the statement key' => [static function (TestProvider $p): void {
            $p->envelopeSigningKey = TestProvider::STATEMENT_KID;
        }, 'envelope_invalid'];
        yield 'a jku that is not the envelope address' => [static function (TestProvider $p): void {
            $p->envelopeHeader = ['jku' => TestProvider::STATEMENT_JWKS];
        }, 'envelope_invalid'];
        yield 'a kid only at the statement address' => [static function (TestProvider $p): void {
            $p->envelopeHeader = ['kid' => TestProvider::STATEMENT_KID];
            $p->envelopeSigningKey = TestProvider::STATEMENT_KID;
        }, 'unknown_key'];
    }

    /**
     * @param Closure(TestProvider): void $change
     */
    #[DataProvider('invalidStatements')]
    public function test_an_invalid_statement_is_refused(Closure $change, string $failureType): void
    {
        $change($this->provider);

        $this->assertFailure($this->validate(), $failureType);
    }

    /**
     * @return iterable<string, array{Closure(TestProvider): void, string}>
     */
    public static function invalidStatements(): iterable
    {
        $claims = self::statementClaims(...);

        yield 'another issuer' => [$claims(['iss' => 'abonnee.dezi.nl']), 'statement_invalid'];
        yield 'loa_dezi spelled like loa_authn' => [$claims(['loa_dezi' => TestProvider::LOA_AUTHN]), 'statement_invalid'];
        yield 'another verklaring_id' => [$claims(['verklaring_id' => self::OTHER_UUID]), 'statement_invalid'];
        yield 'nbf beyond the clock skew' => [static function (TestProvider $p): void {
            $p->statementClaims = ['nbf' => (int) $p->now + 61];
        }, 'statement_invalid'];
        yield 'exp passed' => [static function (TestProvider $p): void {
            $p->statementClaims = ['exp' => (int) $p->now];
        }, 'statement_invalid'];
        yield 'exp as a string of digits' => [$claims(['exp' => '1891367200']), 'statement_invalid'];
        yield 'no dezi_nummer' => [$claims(['dezi_nummer' => TestProvider::ABSENT]), 'statement_invalid'];
        yield 'a null dezi_nummer' => [$claims(['dezi_nummer' => null]), 'statement_invalid'];
        yield 'an integer dezi_nummer' => [$claims(['dezi_nummer' => 900000001]), 'statement_invalid'];
        yield 'an empty dezi_nummer' => [$claims(['dezi_nummer' => '']), 'statement_invalid'];
        yield 'a null abonnee_nummer' => [$claims(['abonnee_nummer' => null]), 'statement_invalid'];
        yield 'a null rol_code' => [$claims(['rol_code' => null]), 'statement_invalid'];
        yield 'an empty rol_code' => [$claims(['rol_code' => '']), 'statement_invalid'];
        yield 'a numeric rol_code' => [$claims(['rol_code' => 1.015]), 'statement_invalid'];
        yield 'a null achternaam' => [$claims(['achternaam' => null]), 'statement_invalid'];
        yield 'the string "null"' => [$claims(['voorvoegsel' => 'null']), 'statement_invalid'];
        yield 'signed with the envelope key' => [static function (TestProvider $p): void {
            $p->statementSigningKey = TestProvider::ENVELOPE_KID;
        }, 'statement_invalid'];
        yield 'a jku at the envelope address' => [static function (TestProvider $p): void {
            $p->statementHeader = ['jku' => TestProvider::ENVELOPE_JWKS];
        }, 'statement_invalid'];
        yield 'no jku' => [static function (TestProvider $p): void {
            $p->statementHeader = ['jku' => TestProvider::ABSENT];
        }, 'statement_invalid'];
        yield 'signed with the ID-token key' => [static function (TestProvider $p): void {
            $p->statementHeader = ['kid' => TestProvider::KID];
            $p->statementSigningKey = TestProvider::KID;
        }, 'unknown_key'];
    }

    public function test_a_verklaring_id_that_is_not_a_uuid_is_refused(): void
    {
        $this->provider->envelopeClaims = ['verklaring_id' => 'verklaring-1'];
        $this->provider->statementClaims = ['verklaring_id' => 'verklaring-1'];

        $this->assertFailure($this->validate(), 'statement_invalid');
        self::assertSame(0, $this->statusRequests());
    }

    public function test_a_uuid_with_a_trailing_newline_is_refused_before_the_status_check(): void
    {
        $id = TestProvider::VERKLARING_ID . "\n";
        $this->provider->envelopeClaims = ['verklaring_id' => $id];
        $this->provider->statementClaims = ['verklaring_id' => $id];

        $this->assertFailure($this->validate(), 'statement_invalid');
        self::assertSame(0, $this->statusRequests());
    }

    public function test_the_status_check_uses_the_configured_address_and_never_the_statement_link(): void
    {
        $this->verified($this->validate());

        $urls = array_column($this->provider->requests, 'url');
        self::assertSame(1, $this->statusRequests());
        self::assertContains($this->provider->statusUrl(), $urls);
        self::assertSame([], array_filter($urls, static fn (string $url): bool => str_contains($url, '/statement-link/')));
    }

    public function test_a_revoked_statement_is_refused_and_final(): void
    {
        $this->provider->status = 'ingetrokken';

        $outcome = $this->validate();

        $this->assertFailure($outcome, 'statement_not_active');
        self::assertFalse($outcome->restartable);
    }

    public function test_a_status_check_without_an_answer_is_restartable(): void
    {
        $this->provider->answers[$this->provider->statusUrl()] = static fn (): MockResponse => new MockResponse('', ['http_code' => 503]);

        $outcome = $this->validate();

        $this->assertFailure($outcome, 'status_check_unavailable');
        self::assertTrue($outcome->restartable);
    }

    public function test_a_valid_decision_needs_no_request_at_delivery(): void
    {
        $result = $this->verified($this->validate());
        $this->oidc->clock->sleep(54);

        $recheck = $this->dezi()->recheck($result, $this->configuration()->provider, $this->oidc->clock->now());

        self::assertTrue($recheck->passed);
        self::assertSame($result, $recheck->result);
        self::assertEquals($this->oidc->clock->now()->modify('+6 seconds'), $recheck->validUntil);
        self::assertSame(1, $this->statusRequests());
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function agedDecisions(): iterable
    {
        yield 'within the status timeout of its expiry' => [56];
        yield 'exactly at its expiry' => [60];
        yield 'after its expiry' => [90];
    }

    #[DataProvider('agedDecisions')]
    public function test_an_aged_decision_is_renewed_with_one_request(int $age): void
    {
        $result = $this->verified($this->validate());
        $this->oidc->clock->sleep($age);

        $recheck = $this->dezi()->recheck($result, $this->configuration()->provider, $this->oidc->clock->now());

        self::assertTrue($recheck->passed);
        self::assertSame(2, $this->statusRequests());
        self::assertEquals($this->oidc->clock->now()->modify('+60 seconds'), $recheck->validUntil);
        self::assertSame($result->verifiedClaims(), $recheck->result?->verifiedClaims());
        self::assertEquals($result->hardExpiry(), $recheck->result->hardExpiry());
    }

    public function test_renewal_never_extends_the_hard_expiry(): void
    {
        $result = $this->verified($this->validate());
        $this->oidc->clock->sleep(290);

        $recheck = $this->dezi()->recheck($result, $this->configuration()->provider, $this->oidc->clock->now());

        self::assertTrue($recheck->passed);
        self::assertEquals($result->hardExpiry(), $recheck->validUntil);
        self::assertEquals($result->hardExpiry(), $recheck->result?->hardExpiry());
    }

    public function test_a_renewal_that_finds_the_statement_revoked_fails(): void
    {
        $result = $this->verified($this->validate());
        $this->oidc->clock->sleep(60);
        $this->provider->status = 'ingetrokken';

        $recheck = $this->dezi()->recheck($result, $this->configuration()->provider, $this->oidc->clock->now());

        self::assertFalse($recheck->passed);
        self::assertNull($recheck->result);
        self::assertSame('statement_not_active', $recheck->failureType);
        self::assertFalse($recheck->restartable);
    }

    public function test_a_renewal_without_an_answer_fails_restartably(): void
    {
        $result = $this->verified($this->validate());
        $this->oidc->clock->sleep(60);
        $this->provider->answers[$this->provider->statusUrl()] = static fn (): MockResponse => new MockResponse('', ['error' => 'timeout']);

        $recheck = $this->dezi()->recheck($result, $this->configuration()->provider, $this->oidc->clock->now());

        self::assertFalse($recheck->passed);
        self::assertSame('status_check_unavailable', $recheck->failureType);
        self::assertTrue($recheck->restartable);
        self::assertSame(2, $this->statusRequests());
    }

    /**
     * @param array<string, mixed> $claims
     * @return Closure(TestProvider): void
     */
    private static function envelopeClaims(array $claims): Closure
    {
        return static function (TestProvider $provider) use ($claims): void {
            $provider->envelopeClaims = $claims;
        };
    }

    /**
     * @param array<string, mixed> $claims
     * @return Closure(TestProvider): void
     */
    private static function statementClaims(array $claims): Closure
    {
        return static function (TestProvider $provider) use ($claims): void {
            $provider->statementClaims = $claims;
        };
    }

    /**
     * @param list<array{list<string|int>, mixed}> $changes
     */
    private function validate(array $changes = []): ProfileOutcome
    {
        $configuration = $this->configuration($changes);

        return $this->dezi()->validateLogin($this->login($configuration), $configuration->provider);
    }

    private function dezi(): DeziProfile
    {
        return $this->oidc->deziProfile();
    }

    /**
     * @param list<array{list<string|int>, mixed}> $changes
     */
    private function configuration(array $changes = []): JipConfiguration
    {
        return $this->oidc->configuration($changes);
    }

    private function login(JipConfiguration $configuration): AuthenticatedLogin
    {
        return new AuthenticatedLogin(
            $configuration->provider->oidc->clients['ggd'],
            new ProviderMetadata(
                TestProvider::ISSUER,
                TestProvider::AUTHORIZE,
                TestProvider::TOKEN,
                TestProvider::ID_TOKEN_JWKS,
                TestProvider::USERINFO,
                ['none', 'private_key_jwt'],
            ),
            new IdTokenClaims(TestProvider::SUBJECT, $this->now, []),
            'test-access-token',
            new DateTimeImmutable('@' . $this->now),
        );
    }

    private function verified(ProfileOutcome $outcome): ProfileResult
    {
        self::assertNull($outcome->failureType, $outcome->detail);

        return $outcome->result ?? self::fail('No result.');
    }

    private function assertFailure(ProfileOutcome $outcome, string $failureType): void
    {
        self::assertNull($outcome->result);
        self::assertSame($failureType, $outcome->failureType, $outcome->detail);
    }

    private function statusRequests(): int
    {
        return count(array_filter(
            $this->provider->requests,
            static fn (array $request): bool => str_starts_with($request['url'], TestProvider::STATUS_PREFIX),
        ));
    }
}
