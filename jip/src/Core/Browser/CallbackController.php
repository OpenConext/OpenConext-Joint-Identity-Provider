<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Browser;

use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Core\Profile\ProfileRegistry;
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
            $this->logger->warning('JIP callback {log_id}: state or cookie does not match an attempt at the provider', [
                'log_id' => $transaction->logId,
            ]);

            return $this->restartable(FailureType::CallbackMismatch, $transaction, $configuration);
        }

        $validating = $transaction->validating();
        if (!$this->store->compareAndSet($transaction->id, TransactionState::AtProvider, $validating, $now)) {
            $this->logger->warning('JIP callback {log_id}: the attempt is no longer at the provider', [
                'log_id' => $transaction->logId,
            ]);

            return $this->restartable(FailureType::CallbackMismatch, $transaction, $configuration);
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
                $configuration->provider,
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
                    $outcome->failureType ?? FailureType::ResultCompletionUnavailable->value,
                    $outcome->restartable,
                    $outcome->detail,
                );
            }

            // The account binding and the claim mapping are not implemented yet; never succeed without them.
            return $this->fail(
                $transaction,
                $configuration,
                FailureType::ResultCompletionUnavailable->value,
                false,
                'account binding is not implemented',
            );
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
            return $this->restartable(FailureType::Expired, $validating, $configuration);
        }

        $this->logger->warning('JIP callback {log_id}: failed ({failure_type}: {detail})', [
            'log_id' => $validating->logId,
            'failure_type' => $failureType,
            'detail' => $detail,
        ]);

        return BrowserPages::failure(
            $failureType,
            $restartable,
            $failed,
            $this->restartUrl($failed, $configuration),
            $status,
        );
    }

    private function restartable(FailureType $type, Transaction $transaction, JipConfiguration $configuration): Response
    {
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
