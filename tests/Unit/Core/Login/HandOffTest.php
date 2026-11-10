<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Core\Login;

use DateTimeImmutable;
use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Core\Login\AttemptGenerator;
use JointIdentityProvider\Core\Login\BrowserOutcomeType;
use JointIdentityProvider\Core\Login\HandOff;
use JointIdentityProvider\Core\Result\TransactionRefusal;
use JointIdentityProvider\Core\Transaction\ProviderAttempt;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Oidc\Pkce;
use JointIdentityProvider\Tests\Support\ConfigurationFixture as Fixture;
use JointIdentityProvider\Tests\Support\InMemoryTransactionStore;
use JointIdentityProvider\Tests\Support\OidcFixture;
use JointIdentityProvider\Tests\Support\TestProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use RuntimeException;

/**
 * The hand-off rules of design §12 and §13, without HTTP or a database.
 */
final class HandOffTest extends TestCase
{
    private const string ID = 'tttttttttttttttttttttttttttttttttttttttttt1';
    private const string RETURN_URL = 'https://engine.dev.openconext.local/authentication/idp/process-sraminterrupt?ID=_abc';

    private OidcFixture $oidc;
    private JipConfiguration $configuration;
    private InMemoryTransactionStore $store;
    private ProviderAttempt $attempt;

    protected function setUp(): void
    {
        $this->oidc = new OidcFixture();
        $this->configuration = $this->oidc->configuration();
        $this->store = new InMemoryTransactionStore($this->oidc->clock);
        $this->attempt = new ProviderAttempt(
            str_repeat('s', 43),
            str_repeat('n', 43),
            str_repeat('v', 43),
            str_repeat('c', 43),
            $this->oidc->clock->now(),
        );
    }

    protected function tearDown(): void
    {
        $this->oidc->remove();
    }

    public function test_a_pending_transaction_goes_to_the_provider_with_the_generated_attempt(): void
    {
        $this->store->add($this->transaction(TransactionState::Pending));

        $outcome = $this->handOff()->start(self::ID, $this->configuration);

        self::assertSame(BrowserOutcomeType::Redirect, $outcome->type);
        $url = $outcome->url ?? '';
        self::assertStringStartsWith(TestProvider::AUTHORIZE . '?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        self::assertSame($this->attempt->oidcState, $query['state'] ?? null);
        self::assertSame($this->attempt->oidcNonce, $query['nonce'] ?? null);
        self::assertSame(Pkce::challenge($this->attempt->pkceVerifier), $query['code_challenge'] ?? null);
        self::assertSame($this->attempt->cookieValue, $outcome->cookieValue);
        self::assertFalse($outcome->clearCookie);

        $stored = $this->store->find(self::ID);
        self::assertSame(TransactionState::AtProvider, $stored?->state);
        self::assertEquals($this->attempt, $stored->attempt);
        self::assertSame($stored, $outcome->cookieTransaction);
    }

    public function test_a_skipped_transaction_returns_to_engineblock_without_a_cookie(): void
    {
        $this->store->add($this->transaction(TransactionState::Skipped));

        $outcome = $this->handOff()->start(self::ID, $this->configuration);

        self::assertSame(BrowserOutcomeType::Redirect, $outcome->type);
        self::assertSame(self::RETURN_URL, $outcome->url);
        self::assertNull($outcome->cookieTransaction);
        self::assertSame(TransactionState::Skipped, $this->store->find(self::ID)?->state);
        self::assertSame(0, $this->oidc->provider->countRequests([TestProvider::DISCOVERY]));
    }

    public function test_an_invalid_or_unknown_nonce_is_unknown(): void
    {
        self::assertSame(BrowserOutcomeType::Unknown, $this->handOff()->start(null, $this->configuration)->type);
        self::assertSame(BrowserOutcomeType::Unknown, $this->handOff()->start('short', $this->configuration)->type);
        self::assertSame(BrowserOutcomeType::Unknown, $this->handOff()->start(self::ID, $this->configuration)->type);
    }

    public function test_consumed_takes_precedence_over_expired(): void
    {
        $this->store->add($this->transaction(TransactionState::Consumed));
        $this->oidc->clock->sleep(601);

        $outcome = $this->handOff()->start(self::ID, $this->configuration);

        self::assertSame(BrowserOutcomeType::Failure, $outcome->type);
        self::assertSame('already_used', $outcome->failureType);
        self::assertSame(400, $outcome->status);
    }

    public function test_an_expired_pending_transaction_is_refused_unchanged(): void
    {
        $this->store->add($this->transaction(TransactionState::Pending));
        $this->oidc->clock->sleep(601);

        $outcome = $this->handOff()->start(self::ID, $this->configuration);

        self::assertSame('expired', $outcome->failureType);
        self::assertSame(400, $outcome->status);
        self::assertSame(TransactionState::Pending, $this->store->find(self::ID)?->state);
        self::assertSame(0, $this->oidc->provider->countRequests([TestProvider::DISCOVERY]));
    }

    public function test_a_lost_race_shows_the_state_another_request_set(): void
    {
        $pending = $this->transaction(TransactionState::Pending);
        $this->store->add($pending);
        $this->store->concurrentChange = $pending->atProvider($this->attempt);

        $outcome = $this->handOff()->start(self::ID, $this->configuration);

        self::assertSame(BrowserOutcomeType::InProgress, $outcome->type);
        self::assertNull($outcome->cookieValue);
    }

    public function test_a_store_failure_is_an_internal_error(): void
    {
        $this->store->add($this->transaction(TransactionState::Pending));
        $this->store->failure = new RuntimeException('Store unavailable.');

        $outcome = $this->handOff()->start(self::ID, $this->configuration);

        self::assertSame('internal_error', $outcome->failureType);
        self::assertSame(500, $outcome->status);
        self::assertFalse($outcome->restartable);
    }

    private function handOff(): HandOff
    {
        $attempt = $this->attempt;

        return new HandOff(
            $this->store,
            $this->oidc->client(),
            $this->oidc->clock,
            new NullLogger(),
            new class ($attempt) implements AttemptGenerator {
                public function __construct(private readonly ProviderAttempt $attempt)
                {
                }

                public function generate(DateTimeImmutable $startedAt): ProviderAttempt
                {
                    return $this->attempt;
                }
            },
            new TransactionRefusal(new NullLogger()),
        );
    }

    private function transaction(TransactionState $state): Transaction
    {
        $now = $this->oidc->clock->now();

        return new Transaction(
            self::ID,
            '0123456789abcdef',
            Fixture::SERVICE,
            'http://mock-idp',
            'urn:collab:person:example:jdoe',
            'mock-1',
            $state === TransactionState::Skipped ? '' : '123456789',
            self::RETURN_URL,
            $now->modify('+600 seconds'),
            $state,
            resultDeadline: $state === TransactionState::Skipped ? $now->modify('+600 seconds') : null,
        );
    }
}
