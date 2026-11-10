<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Login;

use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Core\EngineBlock\ReturnUrl;
use JointIdentityProvider\Core\Result\TransactionRefusal;
use JointIdentityProvider\Core\Transaction\FailureType;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionId;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Core\Transaction\TransactionStore;
use JointIdentityProvider\Oidc\OidcClient;
use JointIdentityProvider\Oidc\OidcFailure;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Throwable;

/**
 * The browser hand-off from EngineBlock (design §3, §12, §13). A pending transaction moves to
 * `at_provider` in one atomic step and the browser goes to the provider; a skipped transaction goes
 * straight back to EngineBlock's return URL, without the provider and without a cookie.
 */
final readonly class HandOff
{
    public function __construct(
        private TransactionStore $store,
        private OidcClient $oidc,
        private ClockInterface $clock,
        #[Autowire(service: 'jip.logger')] private LoggerInterface $logger,
        private AttemptGenerator $attempts,
        private TransactionRefusal $refusals,
    ) {
    }

    public function start(?string $nonce, JipConfiguration $configuration): BrowserOutcome
    {
        if ($nonce === null || !TransactionId::isValid($nonce)) {
            return BrowserOutcome::unknown();
        }

        $transaction = null;
        try {
            $transaction = $this->store->find($nonce);
            if ($transaction === null) {
                return BrowserOutcome::unknown();
            }

            return match ($transaction->state) {
                TransactionState::Pending => $this->handOff($transaction, $configuration),
                TransactionState::Skipped => $this->returnToEngineBlock($transaction, $configuration),
                default => $this->stateFor($transaction, $configuration),
            };
        } catch (Throwable $exception) {
            // Messages and traces can contain authentication material.
            $this->logger->error('JIP hand-off {log_id}: internal_error ({exception_class})', [
                'log_id' => $transaction->logId ?? '-',
                'exception_class' => $exception::class,
            ]);

            return BrowserOutcome::failure(
                FailureType::InternalError->value,
                false,
                $transaction,
                null,
                500,
            );
        }
    }

    private function handOff(Transaction $transaction, JipConfiguration $configuration): BrowserOutcome
    {
        $now = $this->clock->now();
        if ($transaction->isExpired($now)) {
            return $this->stateFor($transaction, $configuration);
        }

        $service = $configuration->services[$transaction->serviceId] ?? null;
        $client = $service === null ? null : $configuration->provider->oidc->clients[$service->client] ?? null;
        if ($client === null) {
            $this->logger->error('JIP hand-off {log_id}: the service is no longer configured', [
                'log_id' => $transaction->logId,
            ]);

            return BrowserOutcome::failure(FailureType::ServiceNotConfigured->value, false, $transaction, null);
        }

        $attempt = $this->attempts->generate($now);

        try {
            $url = $this->oidc->authorizationUrl(
                $configuration->provider->oidc,
                $configuration->provider->trust,
                $client,
                $attempt->oidcState,
                $attempt->oidcNonce,
                $attempt->pkceVerifier,
            );
        } catch (OidcFailure $failure) {
            // The transaction stays pending: the state diagram has no step from pending to failed.
            $this->logger->warning('JIP hand-off {log_id}: {failure_type} ({detail})', [
                'log_id' => $transaction->logId,
                'failure_type' => $failure->type->value,
                'detail' => $failure->detail,
            ]);

            return BrowserOutcome::failure(
                $failure->type->value,
                $failure->type->isRestartable(),
                $transaction,
                $service->restartLoginUrl,
                502,
            );
        }

        $atProvider = $transaction->atProvider($attempt);
        if (!$this->store->compareAndSet($transaction->id, TransactionState::Pending, $atProvider, $now)) {
            $current = $this->store->find($transaction->id);

            if ($current === null && !$transaction->isExpired($this->clock->now())) {
                return BrowserOutcome::unknown();
            }

            return $this->stateFor($current ?? $transaction, $configuration);
        }

        $this->logger->info('JIP hand-off {log_id}: to the provider', ['log_id' => $transaction->logId]);

        return BrowserOutcome::redirect($url, $atProvider, $attempt->cookieValue);
    }

    private function returnToEngineBlock(Transaction $transaction, JipConfiguration $configuration): BrowserOutcome
    {
        if ($transaction->isExpired($this->clock->now())) {
            return $this->stateFor($transaction, $configuration);
        }

        if (!ReturnUrl::isValid($transaction->returnUrl, $configuration->engineBlock->returnUrlPrefix)) {
            $this->logger->error('JIP hand-off {log_id}: the stored return URL is not EngineBlock\'s', [
                'log_id' => $transaction->logId,
            ]);

            return BrowserOutcome::failure(FailureType::InvalidReturnUrl->value, false, $transaction, null);
        }

        $this->logger->info('JIP hand-off {log_id}: skipped, back to EngineBlock', ['log_id' => $transaction->logId]);

        return BrowserOutcome::redirect($transaction->returnUrl, $transaction);
    }

    /**
     * The page for a transaction that this hand-off does not move.
     */
    private function stateFor(Transaction $transaction, JipConfiguration $configuration): BrowserOutcome
    {
        $restartUrl = ($configuration->services[$transaction->serviceId] ?? null)?->restartLoginUrl;

        $type = TransactionRefusal::reason($transaction, $this->clock->now());
        if ($type !== null) {
            $this->refusals->log('hand-off', $transaction, $type);

            return BrowserOutcome::failure(
                $type->value,
                $type->isRestartable(),
                $transaction,
                $restartUrl,
                400,
            );
        }

        return $transaction->state === TransactionState::Failed
            ? BrowserOutcome::failure(
                $transaction->failureType ?? TransactionState::Failed->value,
                $transaction->failureRestartable,
                $transaction,
                $restartUrl,
            )
            : BrowserOutcome::inProgress($transaction);
    }
}
