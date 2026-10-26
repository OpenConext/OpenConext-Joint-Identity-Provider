<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Profile\Dezi;

use DateTimeImmutable;
use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Oidc\AuthenticatedLogin;
use JointIdentityProvider\Oidc\Discovery\ProviderMetadata;
use JointIdentityProvider\Oidc\IdToken\IdTokenClaims;
use JointIdentityProvider\Profile\Dezi\DeziFailure;
use JointIdentityProvider\Profile\Dezi\UserInfoReader;
use JointIdentityProvider\Tests\Support\OidcFixture;
use JointIdentityProvider\Tests\Support\TestProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Fetching and decrypting UserInfo (design §14 "UserInfo", "The connector's decryption keys", §18
 * "Client keys").
 */
final class UserInfoReaderTest extends TestCase
{
    private OidcFixture $oidc;
    private TestProvider $provider;

    protected function setUp(): void
    {
        $this->oidc = new OidcFixture();
        $this->provider = $this->oidc->provider;
        $this->provider->now = $this->oidc->clock->now()->getTimestamp();
        $this->provider->userInfoRecipient = $this->oidc->decryptionCertificate();
    }

    protected function tearDown(): void
    {
        $this->oidc->remove();
    }

    public function test_userinfo_is_fetched_with_the_access_token_and_decrypted(): void
    {
        self::assertSame($this->provider->envelope(), $this->read());

        $request = $this->provider->requests[0];
        self::assertSame(['GET', TestProvider::USERINFO], [$request['method'], $request['url']]);
        self::assertContains('Authorization: Bearer test-access-token', self::headers($request['options']));
    }

    /**
     * @param array<string, mixed> $header
     */
    #[DataProvider('unsupportedHeaders')]
    public function test_only_rsa_oaep_with_a256cbc_hs512_is_accepted(array $header): void
    {
        $this->provider->userInfoHeader = $header;

        $this->assertRefused('userinfo_invalid');
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function unsupportedHeaders(): iterable
    {
        yield 'RSA-OAEP-256' => [['alg' => 'RSA-OAEP-256']];
        yield 'RSA1_5' => [['alg' => 'RSA1_5']];
        yield 'dir' => [['alg' => 'dir']];
        yield 'A256GCM' => [['enc' => 'A256GCM']];
        yield 'A128CBC-HS256' => [['enc' => 'A128CBC-HS256']];
        yield 'no enc' => [['enc' => TestProvider::ABSENT]];
        yield 'compression' => [['zip' => 'DEF']];
        yield 'a critical header' => [['crit' => ['exp'], 'exp' => 1]];
    }

    public function test_a_signed_but_unencrypted_answer_is_refused(): void
    {
        $envelope = $this->provider->envelope();
        $this->provider->answers[TestProvider::USERINFO] = static fn (): MockResponse => new MockResponse($envelope);

        $this->assertRefused('userinfo_invalid');
    }

    /**
     * @return iterable<string, array{MockResponse, string, bool}>
     */
    public static function answers(): iterable
    {
        yield '401' => [new MockResponse('', ['http_code' => 401]), 'userinfo_refused', false];
        yield '404' => [new MockResponse('', ['http_code' => 404]), 'userinfo_refused', false];
        yield '503' => [new MockResponse('', ['http_code' => 503]), 'userinfo_unavailable', true];
        yield 'a redirect' => [new MockResponse('', ['http_code' => 302, 'response_headers' => ['Location' => TestProvider::ISSUER]]), 'userinfo_unavailable', true];
        yield 'a timeout' => [new MockResponse('', ['error' => 'timeout']), 'userinfo_unavailable', true];
    }

    #[DataProvider('answers')]
    public function test_an_answer_without_a_jwe_fails(MockResponse $response, string $failureType, bool $restartable): void
    {
        $this->provider->answers[TestProvider::USERINFO] = static fn (): MockResponse => $response;

        $failure = $this->assertRefused($failureType);

        self::assertSame($restartable, $failure->type->isRestartable());
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function headerKids(): iterable
    {
        yield 'the kid of the decrypting key' => ['jip-2026'];
        yield 'the kid of another configured key' => ['jip-2027'];
        yield 'an unknown kid' => ['unknown'];
        yield 'no kid' => [null];
    }

    #[DataProvider('headerKids')]
    public function test_every_configured_key_is_tried_whatever_the_kid(?string $kid): void
    {
        $this->provider->userInfoHeader = $kid === null ? [] : ['kid' => $kid];

        self::assertSame($this->provider->envelope(), $this->read($this->twoKeys()));
    }

    public function test_after_the_previous_key_is_removed_its_answers_no_longer_decrypt(): void
    {
        $directory = $this->oidc->configFixture->directory;
        $this->oidc->configFixture->writeKeyPair('decryption-2027');

        $failure = $this->assertRefused('userinfo_not_decrypted', [[['provider', 'clients', 'ggd', 'decryption_keys'], [
            ['certificate' => $directory . '/decryption-2027.crt', 'private_key' => $directory . '/decryption-2027.pem', 'kid' => 'jip-2027'],
        ]]]);

        self::assertFalse($failure->type->isRestartable());
    }

    public function test_an_answer_encrypted_to_an_unknown_key_is_not_decrypted(): void
    {
        $this->oidc->configFixture->writeKeyPair('decryption-unregistered');
        $pem = file_get_contents($this->oidc->configFixture->directory . '/decryption-unregistered.crt');
        $this->provider->userInfoRecipient = is_string($pem) ? $pem : self::fail('No certificate.');

        $this->assertRefused('userinfo_not_decrypted', $this->twoKeys());
    }

    public function test_a_tampered_ciphertext_is_not_decrypted(): void
    {
        $parts = explode('.', $this->provider->userInfo());
        $parts[3] = TestProvider::b64(random_bytes(64));
        $tampered = implode('.', $parts);
        $this->provider->answers[TestProvider::USERINFO] = static fn (): MockResponse => new MockResponse($tampered);

        $this->assertRefused('userinfo_not_decrypted');
    }

    /**
     * The previous key (the provider's recipient) after the new one, as during a replacement.
     *
     * @return list<array{list<string|int>, mixed}>
     */
    private function twoKeys(): array
    {
        $directory = $this->oidc->configFixture->directory;
        $this->oidc->configFixture->writeKeyPair('decryption-2027');

        return [[['provider', 'clients', 'ggd', 'decryption_keys'], [
            ['certificate' => $directory . '/decryption-2027.crt', 'private_key' => $directory . '/decryption-2027.pem', 'kid' => 'jip-2027'],
            ['certificate' => $directory . '/decryption.crt', 'private_key' => $directory . '/decryption.pem', 'kid' => 'jip-2026'],
        ]]];
    }

    /**
     * @param list<array{list<string|int>, mixed}> $changes
     */
    private function read(array $changes = []): string
    {
        return new UserInfoReader($this->oidc->http)->read($this->login($this->oidc->configuration($changes)));
    }

    /**
     * @param list<array{list<string|int>, mixed}> $changes
     */
    private function assertRefused(string $failureType, array $changes = []): DeziFailure
    {
        try {
            $this->read($changes);
        } catch (DeziFailure $failure) {
            self::assertSame($failureType, $failure->type->value, $failure->detail);

            return $failure;
        }

        self::fail('UserInfo was accepted.');
    }

    private function login(JipConfiguration $configuration): AuthenticatedLogin
    {
        $now = $this->oidc->clock->now();

        return new AuthenticatedLogin(
            $configuration->provider->oidc->clients['ggd'],
            new ProviderMetadata(
                TestProvider::ISSUER,
                TestProvider::AUTHORIZE,
                TestProvider::TOKEN,
                TestProvider::ID_TOKEN_JWKS,
                TestProvider::USERINFO,
                ['private_key_jwt'],
            ),
            new IdTokenClaims(TestProvider::SUBJECT, $now->getTimestamp(), []),
            'test-access-token',
            new DateTimeImmutable('@' . $now->getTimestamp()),
        );
    }

    /**
     * @param array<string, mixed> $options
     * @return list<string>
     */
    private static function headers(array $options): array
    {
        $normalized = $options['normalized_headers'] ?? null;
        $headers = is_array($normalized) ? ($normalized['authorization'] ?? null) : null;

        return is_array($headers) ? array_values(array_filter($headers, 'is_string')) : [];
    }
}
