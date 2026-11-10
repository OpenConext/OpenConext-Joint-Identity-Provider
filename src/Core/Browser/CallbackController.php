<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Browser;

use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Core\EngineBlock\LogFields;
use JointIdentityProvider\Core\EngineBlock\ReturnUrl;
use JointIdentityProvider\Core\Profile\ProfileRegistry;
use JointIdentityProvider\Core\Profile\ProfileResult;
use JointIdentityProvider\Core\Result\ResultAcceptance;
use JointIdentityProvider\Core\Transaction\FailureType;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Core\Transaction\TransactionStore;
use JointIdentityProvider\Oidc\Configuration\ClientConfiguration;
use JointIdentityProvider\Oidc\Jose\Base64Url;
use JointIdentityProvider\Oidc\OidcClient;
use JointIdentityProvider\Oidc\OidcFailure;
use JointIdentityProvider\Oidc\OidcFailureType;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Throwable;

/**
 * The provider's `redirect_uri` (design §3, §13, §14). `state` and the transaction's own cookie must
 * match an `at_provider` transaction before anything else happens; a mismatch changes no transaction.
 * The transaction then moves to `validating` in one atomic step, so a callback is processed once. Any
 * failed check moves it to `failed`. Success needs the profile and the core's own checks.
 */
final readonly class CallbackController
{
    private const int MAX_CODE_LENGTH = 2048;

    public function __construct(
        private ConfigurationLoader $loader,
        private TransactionStore $store,
        private OidcClient $oidc,
        private ProfileRegistry $profiles,
        private ClockInterface $clock,
        private LoggerInterface $logger,
    ) {
    }

    #[Route(ClientConfiguration::CALLBACK_PATH, name: 'jip_oidc_callback', methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $configuration = $this->loader->load();
        $query = $request->query->all();

        $state = $query['state'] ?? null;
        if (!is_string($state) || !Base64Url::isRandomToken($state)) {
            $this->logger->warning('JIP callback: no valid state');

            return BrowserPages::unknown();
        }

        $transaction = $this->store->findByOidcState($state);
        if ($transaction === null) {
            $this->logger->warning('JIP callback: the state belongs to no transaction');

            return BrowserPages::unknown();
        }

        $now = $this->clock->now();
        if ($transaction->state === TransactionState::Consumed) {
            return $this->restartable(FailureType::AlreadyUsed, $transaction, $configuration);
        }
        if ($transaction->isExpired($now)) {
            return $this->restartable(FailureType::Expired, $transaction, $configuration);
        }
        if ($transaction->state === TransactionState::Failed) {
            return BrowserPages::failure(
                $transaction->failureType ?? TransactionState::Failed->value,
                $transaction->failureRestartable,
                $transaction,
                $this->restartUrl($transaction, $configuration),
            );
        }

        $cookie = $request->cookies->all()[TransactionCookie::name($transaction)] ?? null;
        if (
            $transaction->state !== TransactionState::AtProvider || $transaction->attempt === null
            || !is_string($cookie) || !hash_equals($transaction->attempt->cookieValue, $cookie)
        ) {
            return $this->restartable(FailureType::CallbackMismatch, $transaction, $configuration);
        }

        $validating = $transaction->validating();
        if (!$this->store->compareAndSet($transaction->id, TransactionState::AtProvider, $validating, $now)) {
            return $this->notUpdated($transaction, $configuration);
        }

        try {
            $response = $this->validate($validating, $query, $configuration);
        } catch (Throwable $exception) {
            $response = $this->internalError($validating, $configuration, $exception);
        }
        $response->headers->setCookie(TransactionCookie::clear($validating));

        return $response;
    }

    /**
     * @param array<mixed> $query
     */
    private function validate(Transaction $transaction, array $query, JipConfiguration $configuration): Response
    {
        $attempt = $transaction->attempt;
        $service = $configuration->services[$transaction->serviceId] ?? null;
        $client = $service === null ? null : $configuration->provider->oidc->clients[$service->client] ?? null;
        $profile = $this->profiles->get($configuration->provider->profile);
        if ($attempt === null || $client === null || $profile === null) {
            $type = FailureType::ServiceNotConfigured->value;

            return $this->fail($transaction, $configuration, $type, false, 'no client');
        }

        if (array_key_exists('error', $query)) {
            $type = ($query['error'] ?? null) === 'access_denied'
                ? OidcFailureType::ProviderCancelled
                : OidcFailureType::ProviderError;

            return $this->fail(
                $transaction,
                $configuration,
                $type->value,
                $type->isRestartable(),
                'error at the callback',
            );
        }

        $code = $query['code'] ?? null;
        if (!is_string($code) || $code === '' || strlen($code) > self::MAX_CODE_LENGTH) {
            $type = OidcFailureType::CallbackInvalid;

            return $this->fail($transaction, $configuration, $type->value, $type->isRestartable(), 'no valid code');
        }

        try {
            $login = $this->oidc->completeLogin(
                $configuration->provider->oidc,
                $configuration->provider->trust,
                $client,
                $code,
                $attempt->pkceVerifier,
                $attempt->oidcNonce,
                $attempt->startedAt,
            );

            $this->logger->info('JIP callback {log_id}: OIDC checks passed; {profile} profile validation', [
                'log_id' => $transaction->logId,
                'profile' => $profile->name(),
            ]);

            $outcome = $profile->validateLogin($login, $configuration->provider);
            if ($outcome->result === null) {
                return $this->fail(
                    $transaction,
                    $configuration,
                    $outcome->failureType ?? FailureType::InternalError->value,
                    $outcome->restartable,
                    $profile->name() . ' profile, ' . $outcome->detail,
                );
            }

            return $this->succeed($transaction, $outcome->result, $configuration);
        } catch (OidcFailure $failure) {
            return $this->fail(
                $transaction,
                $configuration,
                $failure->type->value,
                $failure->type->isRestartable(),
                $failure->detail,
            );
        }
    }

    /**
     * Applies the core's checks to the verified profile result; on success the transaction moves to
     * `succeeded` and the browser returns to EngineBlock with only the request ID in the URL.
     */
    private function succeed(
        Transaction $validating,
        ProfileResult $result,
        JipConfiguration $configuration,
    ): Response {
        $accepted = ResultAcceptance::accept($validating, $result, $configuration, $this->clock->now());
        if ($accepted instanceof FailureType) {
            return $this->fail($validating, $configuration, $accepted->value, $accepted->isRestartable(), 'core check');
        }

        if (!ReturnUrl::isValid($validating->returnUrl, $configuration->engineBlock->returnUrlPrefix)) {
            $type = FailureType::InvalidReturnUrl;

            return $this->fail($validating, $configuration, $type->value, false, 'stored return URL');
        }

        $now = $this->clock->now();
        if (!$this->store->compareAndSet($validating->id, TransactionState::Validating, $accepted, $now)) {
            return $this->notUpdated($validating, $configuration);
        }

        $this->logger->info('JIP callback {log_id}: succeeded, back to EngineBlock', ['log_id' => $validating->logId]);

        return BrowserPages::redirect($validating->returnUrl);
    }

    private function internalError(
        Transaction $transaction,
        JipConfiguration $configuration,
        Throwable $exception,
    ): Response {
        // Exception messages and traces can contain received credentials; log only the class.
        $this->logger->error('JIP callback {log_id}: internal_error ({exception_class})', [
            'log_id' => $transaction->logId,
            'exception_class' => $exception::class,
        ]);

        try {
            return $this->fail(
                $transaction,
                $configuration,
                FailureType::InternalError->value,
                false,
                'unexpected internal failure',
                Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        } catch (Throwable $storageException) {
            $this->logger->error('JIP callback {log_id}: cannot record internal_error ({exception_class})', [
                'log_id' => $transaction->logId,
                'exception_class' => $storageException::class,
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

    private function fail(
        Transaction $validating,
        JipConfiguration $configuration,
        string $failureType,
        bool $restartable,
        string $detail,
        int $status = Response::HTTP_FORBIDDEN,
    ): Response {
        $failed = $validating->failed($failureType, $restartable);
        if (!$this->store->compareAndSet($validating->id, TransactionState::Validating, $failed, $this->clock->now())) {
            return $this->notUpdated($validating, $configuration);
        }

        $this->logger->warning(
            'JIP callback {log_id}: failed ({failure_type}: {detail}) for service {service}, organisation'
            . ' {organisation}, policy version {policy_version} at start, EngineBlock request {eb_request_id}',
            [
                'log_id' => $validating->logId,
                'failure_type' => $failureType,
                'detail' => $detail,
            ] + LogFields::correlation($validating),
        );

        return BrowserPages::failure(
            $failureType,
            $restartable,
            $failed,
            $this->restartUrl($failed, $configuration),
            $status,
        );
    }

    private function notUpdated(Transaction $transaction, JipConfiguration $configuration): Response
    {
        $current = $this->store->find($transaction->id) ?? $transaction;
        $type = match (true) {
            $current->state === TransactionState::Consumed => FailureType::AlreadyUsed,
            $current->isExpired($this->clock->now()) => FailureType::Expired,
            default => FailureType::CallbackMismatch,
        };

        return $this->restartable($type, $current, $configuration);
    }

    private function restartable(FailureType $type, Transaction $transaction, JipConfiguration $configuration): Response
    {
        $this->logger->warning(
            'JIP callback {log_id}: refused ({failure_type}); transaction unchanged ({state})'
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
            $this->restartUrl($transaction, $configuration),
            Response::HTTP_BAD_REQUEST,
        );
    }

    private function restartUrl(Transaction $transaction, JipConfiguration $configuration): ?string
    {
        return ($configuration->services[$transaction->serviceId] ?? null)?->restartLoginUrl;
    }
}
