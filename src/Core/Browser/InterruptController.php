<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Browser;

use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Core\EngineBlock\LogFields;
use JointIdentityProvider\Core\EngineBlock\ReturnUrl;
use JointIdentityProvider\Core\Transaction\FailureType;
use JointIdentityProvider\Core\Transaction\ProviderAttempt;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionId;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Core\Transaction\TransactionStore;
use JointIdentityProvider\Oidc\Jose\Base64Url;
use JointIdentityProvider\Oidc\OidcClient;
use JointIdentityProvider\Oidc\OidcFailure;
use JointIdentityProvider\Oidc\Pkce;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Throwable;

/**
 * The browser hand-off from EngineBlock (design §3, §12, §13). A pending transaction moves to
 * `at_provider` in one atomic step and the browser goes to the provider; a skipped transaction goes
 * straight back to EngineBlock's return URL, without the provider and without a cookie.
 */
final readonly class InterruptController
{
    public function __construct(
        private ConfigurationLoader $loader,
        private TransactionStore $store,
        private OidcClient $oidc,
        private ClockInterface $clock,
        private LoggerInterface $logger,
    ) {
    }

    #[Route('/interrupt', name: 'jip_interrupt', methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $configuration = $this->loader->load();

        $nonce = $request->query->all()['nonce'] ?? null;
        if (!is_string($nonce) || !TransactionId::isValid($nonce)) {
            return BrowserPages::unknown();
        }

        $transaction = null;
        try {
            $transaction = $this->store->find($nonce);
            if ($transaction === null) {
                return BrowserPages::unknown();
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

            return BrowserPages::failure(
                FailureType::InternalError->value,
                false,
                $transaction,
                null,
                Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }
    }

    private function handOff(Transaction $transaction, JipConfiguration $configuration): Response
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

            return BrowserPages::failure(FailureType::ServiceNotConfigured->value, false, $transaction, null);
        }

        $attempt = new ProviderAttempt(
            Base64Url::randomToken(),
            Base64Url::randomToken(),
            Pkce::verifier(),
            Base64Url::randomToken(),
            $now,
        );

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

            return BrowserPages::failure(
                $failure->type->value,
                $failure->type->isRestartable(),
                $transaction,
                $service->restartLoginUrl,
                Response::HTTP_BAD_GATEWAY,
            );
        }

        $atProvider = $transaction->atProvider($attempt);
        if (!$this->store->compareAndSet($transaction->id, TransactionState::Pending, $atProvider, $now)) {
            $current = $this->store->find($transaction->id);

            if ($current === null && !$transaction->isExpired($this->clock->now())) {
                return BrowserPages::unknown();
            }

            return $this->stateFor($current ?? $transaction, $configuration);
        }

        $this->logger->info('JIP hand-off {log_id}: to the provider', ['log_id' => $transaction->logId]);

        $response = BrowserPages::redirect($url);
        $response->headers->setCookie(TransactionCookie::create($atProvider, $attempt->cookieValue));

        return $response;
    }

    private function returnToEngineBlock(Transaction $transaction, JipConfiguration $configuration): Response
    {
        if ($transaction->isExpired($this->clock->now())) {
            return $this->stateFor($transaction, $configuration);
        }

        if (!ReturnUrl::isValid($transaction->returnUrl, $configuration->engineBlock->returnUrlPrefix)) {
            $this->logger->error('JIP hand-off {log_id}: the stored return URL is not EngineBlock\'s', [
                'log_id' => $transaction->logId,
            ]);

            return BrowserPages::failure(FailureType::InvalidReturnUrl->value, false, $transaction, null);
        }

        $this->logger->info('JIP hand-off {log_id}: skipped, back to EngineBlock', ['log_id' => $transaction->logId]);

        return BrowserPages::redirect($transaction->returnUrl);
    }

    /**
     * The page for a transaction that this hand-off does not move.
     */
    private function stateFor(Transaction $transaction, JipConfiguration $configuration): Response
    {
        $restartUrl = ($configuration->services[$transaction->serviceId] ?? null)?->restartLoginUrl;

        if ($transaction->state === TransactionState::Consumed || $transaction->isExpired($this->clock->now())) {
            $type = $transaction->state === TransactionState::Consumed
                ? FailureType::AlreadyUsed
                : FailureType::Expired;
            $this->logger->warning(
                'JIP hand-off {log_id}: refused ({failure_type}); transaction unchanged ({state})'
                . ' for service {service}, organisation {organisation},'
                . ' policy version {policy_version} at start, EngineBlock request {eb_request_id}',
                [
                    'log_id' => $transaction->logId,
                    'failure_type' => $type->value,
                    'state' => $transaction->state->value,
                ] + LogFields::correlation($transaction),
            );

            return BrowserPages::failure(
                $type->value,
                $type->isRestartable(),
                $transaction,
                $restartUrl,
                Response::HTTP_BAD_REQUEST,
            );
        }

        return $transaction->state === TransactionState::Failed
            ? BrowserPages::failure(
                $transaction->failureType ?? TransactionState::Failed->value,
                $transaction->failureRestartable,
                $transaction,
                $restartUrl,
            )
            : BrowserPages::inProgress($transaction);
    }
}
