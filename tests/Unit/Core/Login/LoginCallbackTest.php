<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Core\Login;

use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Core\Login\BrowserOutcome;
use JointIdentityProvider\Core\Login\BrowserOutcomeType;
use JointIdentityProvider\Core\Login\LoginCallback;
use JointIdentityProvider\Core\Profile\ProfileRegistry;
use JointIdentityProvider\Core\Result\TransactionRefusal;
use JointIdentityProvider\Core\Transaction\ProviderAttempt;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Tests\Support\ConfigurationFixture as Fixture;
use JointIdentityProvider\Tests\Support\InMemoryTransactionStore;
use JointIdentityProvider\Tests\Support\OidcFixture;
use JointIdentityProvider\Tests\Support\TestProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use RuntimeException;

/**
 * The callback rules of design §13 and §14 up to the profile, without HTTP or a database.
 */
final class LoginCallbackTest extends TestCase
{
    private const string ID = 'tttttttttttttttttttttttttttttttttttttttttt1';
    private const string LOG_ID = '0123456789abcdef';
    private const string STATE = 'sssssssssssssssssssssssssssssssssssssssssss';
    private const string COOKIE = 'ccccccccccccccccccccccccccccccccccccccccccc';

    private OidcFixture $oidc;
    private JipConfiguration $configuration;
    private InMemoryTransactionStore $store;

    protected function setUp(): void
    {
        $this->oidc = new OidcFixture();
        $this->configuration = $this->oidc->configuration();
        $this->store = new InMemoryTransactionStore($this->oidc->clock);
    }

    protected function tearDown(): void
    {
        $this->oidc->remove();
    }

    /**
     * @param array<string, mixed> $query
     */
    #[DataProvider('unknownStates')]
    public function test_an_invalid_or_unknown_state_is_unknown(array $query): void
    {
        $this->store->add($this->transaction(TransactionState::AtProvider));

        self::assertSame(BrowserOutcomeType::Unknown, $this->complete($query)->type);
        self::assertSame(TransactionState::AtProvider, $this->store->find(self::ID)?->state);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function unknownStates(): iterable
    {
        yield 'absent' => [['code' => 'the-code']];
        yield 'not a token' => [['state' => 'short']];
        yield 'an array' => [['state' => [self::STATE]]];
        yield 'another transaction' => [['state' => str_repeat('x', 43)]];
    }

    public function test_consumed_takes_precedence_over_expired(): void
    {
        $this->store->add($this->transaction(TransactionState::Consumed));
        $this->oidc->clock->sleep(601);

        $outcome = $this->complete(['state' => self::STATE, 'code' => 'the-code']);

        self::assertSame('already_used', $outcome->failureType);
        self::assertSame(400, $outcome->status);
        self::assertFalse($outcome->clearCookie);
    }

    public function test_an_expired_transaction_is_refused_unchanged(): void
    {
        $this->store->add($this->transaction(TransactionState::AtProvider));
        $this->oidc->clock->sleep(601);

        $outcome = $this->complete(['state' => self::STATE, 'code' => 'the-code']);

        self::assertSame('expired', $outcome->failureType);
        self::assertSame(TransactionState::AtProvider, $this->store->find(self::ID)?->state);
    }

    /**
     * @param array<string, mixed> $cookies
     */
    #[DataProvider('mismatchedCookies')]
    public function test_a_missing_or_wrong_cookie_changes_nothing(array $cookies): void
    {
        $this->store->add($this->transaction(TransactionState::AtProvider));

        $outcome = $this->complete(['state' => self::STATE, 'code' => 'the-code'], $cookies);

        self::assertSame('callback_mismatch', $outcome->failureType);
        self::assertSame(400, $outcome->status);
        self::assertFalse($outcome->clearCookie);
        self::assertSame(TransactionState::AtProvider, $this->store->find(self::ID)?->state);
        self::assertSame(0, $this->oidc->provider->countRequests([TestProvider::TOKEN]));
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function mismatchedCookies(): iterable
    {
        yield 'absent' => [[]];
        yield 'wrong value' => [[self::LOG_ID => str_repeat('d', 43)]];
        yield 'another transaction' => [['fedcba9876543210' => self::COOKIE]];
        yield 'not a string' => [[self::LOG_ID => [self::COOKIE]]];
    }

    public function test_a_callback_for_a_transaction_that_is_not_at_the_provider_changes_nothing(): void
    {
        $this->store->add($this->transaction(TransactionState::AtProvider)->validating());

        $outcome = $this->complete(['state' => self::STATE, 'code' => 'the-code']);

        self::assertSame('callback_mismatch', $outcome->failureType);
        self::assertSame(TransactionState::Validating, $this->store->find(self::ID)?->state);
    }

    public function test_a_lost_race_to_validating_changes_nothing_and_keeps_the_cookie(): void
    {
        $atProvider = $this->transaction(TransactionState::AtProvider);
        $this->store->add($atProvider);
        $this->store->concurrentChange = $atProvider->validating();

        $outcome = $this->complete(['state' => self::STATE, 'code' => 'the-code']);

        self::assertSame('callback_mismatch', $outcome->failureType);
        self::assertFalse($outcome->clearCookie);
        self::assertSame(0, $this->oidc->provider->countRequests([TestProvider::TOKEN]));
    }

    /**
     * @param array<string, mixed> $query
     */
    #[DataProvider('failedCallbacks')]
    public function test_a_failed_callback_fails_the_transaction_and_clears_the_cookie(
        array $query,
        string $failureType,
        bool $restartable,
    ): void {
        $this->store->add($this->transaction(TransactionState::AtProvider));

        $outcome = $this->complete(['state' => self::STATE] + $query);

        self::assertSame(BrowserOutcomeType::Failure, $outcome->type);
        self::assertSame($failureType, $outcome->failureType);
        self::assertSame($restartable, $outcome->restartable);
        self::assertSame(403, $outcome->status);
        self::assertTrue($outcome->clearCookie);
        $stored = $this->store->find(self::ID);
        self::assertSame(TransactionState::Failed, $stored?->state);
        self::assertSame($failureType, $stored->failureType);
        self::assertSame(0, $this->oidc->provider->countRequests([TestProvider::TOKEN]));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string, bool}>
     */
    public static function failedCallbacks(): iterable
    {
        yield 'cancelled' => [['error' => 'access_denied'], 'provider_cancelled', true];
        yield 'provider error' => [['error' => 'server_error', 'code' => 'the-code'], 'provider_error', true];
        yield 'no code' => [[], 'callback_invalid', false];
        yield 'empty code' => [['code' => ''], 'callback_invalid', false];
        yield 'long code' => [['code' => str_repeat('a', 2049)], 'callback_invalid', false];
    }

    public function test_a_missing_profile_fails_the_transaction_as_not_configured(): void
    {
        $this->store->add($this->transaction(TransactionState::AtProvider));

        $outcome = $this->complete(['state' => self::STATE, 'code' => 'the-code'], profiles: new ProfileRegistry([]));

        self::assertSame('service_not_configured', $outcome->failureType);
        self::assertFalse($outcome->restartable);
        self::assertTrue($outcome->clearCookie);
        self::assertSame(TransactionState::Failed, $this->store->find(self::ID)?->state);
    }

    public function test_an_unexpected_exception_is_an_internal_error_and_fails_the_transaction(): void
    {
        $this->store->add($this->transaction(TransactionState::AtProvider));
        $this->oidc->provider->answers[TestProvider::TOKEN] = static fn () => throw new RuntimeException('boom');

        $outcome = $this->complete(['state' => self::STATE, 'code' => 'the-code']);

        self::assertSame('internal_error', $outcome->failureType);
        self::assertSame(500, $outcome->status);
        self::assertTrue($outcome->clearCookie);
        self::assertSame('internal_error', $this->store->find(self::ID)?->failureType);
    }

    /**
     * @param array<string, mixed> $query
     * @param array<string, mixed>|null $cookies
     */
    private function complete(array $query, ?array $cookies = null, ?ProfileRegistry $profiles = null): BrowserOutcome
    {
        $callback = new LoginCallback(
            $this->store,
            $this->oidc->client(),
            $profiles ?? new ProfileRegistry([$this->oidc->deziProfile()]),
            $this->oidc->clock,
            new NullLogger(),
            new TransactionRefusal(new NullLogger()),
        );

        return $callback->complete($query, $cookies ?? [self::LOG_ID => self::COOKIE], $this->configuration);
    }

    private function transaction(TransactionState $state): Transaction
    {
        $now = $this->oidc->clock->now();
        $pending = new Transaction(
            self::ID,
            self::LOG_ID,
            Fixture::SERVICE,
            'http://mock-idp',
            'urn:collab:person:example:jdoe',
            'mock-1',
            '123456789',
            'https://engine.dev.openconext.local/authentication/idp/process-sraminterrupt?ID=_abc',
            $now->modify('+600 seconds'),
            TransactionState::Pending,
        );
        $atProvider = $pending->atProvider(
            new ProviderAttempt(self::STATE, str_repeat('n', 43), str_repeat('v', 43), self::COOKIE, $now),
        );

        return match ($state) {
            TransactionState::AtProvider => $atProvider,
            TransactionState::Consumed => $atProvider->consumed(),
            default => throw new RuntimeException('Not a state these tests start from.'),
        };
    }
}
