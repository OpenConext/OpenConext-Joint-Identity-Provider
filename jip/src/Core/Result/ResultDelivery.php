<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Result;

use DateTimeImmutable;
use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Core\EngineBlock\LogFields;
use JointIdentityProvider\Core\Profile\ProfileRegistry;
use JointIdentityProvider\Core\Profile\ProfileResult;
use JointIdentityProvider\Core\Transaction\FailureType;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Core\Transaction\TransactionStore;
use LogicException;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use SensitiveParameter;

/**
 * Delivers a transaction's result to EngineBlock once (design §12, §13). Checks the stored service and
 * organisation against the current approved policy, runs the profile's recheck for a `succeeded`
 * transaction (at most one outgoing request), checks the current policy again and then consumes the
 * transaction in one atomic step that also checks its state, its hard deadline and the validity of the
 * recheck. A refusal moves a still-unconsumed transaction to `failed`; no path releases attributes
 * without consuming.
 */
final readonly class ResultDelivery
{
    public const string VERIFIED = 'verified';
    public const string SKIPPED = 'skipped';

    public function __construct(
        private ConfigurationLoader $loader,
        private TransactionStore $store,
        private ProfileRegistry $profiles,
        private ClockInterface $clock,
        private LoggerInterface $logger,
    ) {
    }

    public function deliver(
        #[SensitiveParameter] string $transactionId,
        JipConfiguration $configuration,
    ): DeliveryOutcome {
        $transaction = $this->store->find($transactionId);
        if ($transaction === null) {
            $this->logger->warning('JIP result: unknown transaction');

            return DeliveryOutcome::notFound();
        }
        if ($transaction->state === TransactionState::Consumed) {
            return $this->refuseUnchanged($transaction, FailureType::AlreadyUsed, $configuration);
        }
        if ($transaction->isExpired($this->clock->now())) {
            return $this->refuseUnchanged($transaction, FailureType::Expired, $configuration);
        }
        if (!in_array($transaction->state, [TransactionState::Succeeded, TransactionState::Skipped], true)) {
            $this->logger->warning('JIP result {log_id}: not deliverable in state {state}', [
                'log_id' => $transaction->logId,
                'state' => $transaction->state->value,
            ]);

            return DeliveryOutcome::forbidden();
        }

        $refusal = self::policyRefusal($transaction, $configuration);
        if ($refusal !== null) {
            return $this->fail($transaction, $refusal->value, $refusal->isRestartable(), $configuration);
        }

        $result = null;
        $validUntil = null;
        if ($transaction->state === TransactionState::Succeeded) {
            $profile = $this->profiles->get($configuration->provider->profile)
                ?? throw new LogicException('The configured profile is not registered.');
            $stored = $transaction->profileResult
                ?? throw new LogicException('A succeeded transaction has no result.');

            $recheck = $profile->recheck($stored, $configuration->provider, $this->clock->now());
            if (!$recheck->passed || $recheck->result === null || $recheck->validUntil === null) {
                return $this->fail(
                    $transaction,
                    $recheck->failureType ?? FailureType::InternalError->value,
                    $recheck->restartable,
                    $configuration,
                );
            }
            $result = $recheck->result;
            $validUntil = $recheck->validUntil;
        }

        // Immediately before consumption: the current approved policy, not the snapshot of this request.
        $current = $this->loader->reload();
        $refusal = self::policyRefusal($transaction, $current);
        if ($refusal !== null) {
            return $this->fail($transaction, $refusal->value, $refusal->isRestartable(), $current);
        }

        $attributes = self::attributes($transaction, $result, $current);
        if ($attributes === null) {
            $type = FailureType::NothingToRelease;

            return $this->fail($transaction, $type->value, $type->isRestartable(), $current);
        }

        if (
            !$this->store->compareAndSet(
                $transaction->id,
                $transaction->state,
                $transaction->consumed(),
                $this->clock->now(),
                $validUntil,
            )
        ) {
            return $this->notConsumed($transaction, $validUntil, $current);
        }

        $this->logger->info(
            'JIP result {log_id}: delivered {outcome} for service {service}, organisation {organisation},'
            . ' policy version {policy_version} at start and {policy_version_delivery} at delivery,'
            . ' EngineBlock request {eb_request_id}',
            [
                'log_id' => $transaction->logId,
                'outcome' => $transaction->state->value,
            ] + self::context($transaction, $current),
        );

        return DeliveryOutcome::delivered($attributes);
    }

    private static function policyRefusal(Transaction $transaction, JipConfiguration $configuration): ?FailureType
    {
        $service = $configuration->services[$transaction->serviceId] ?? null;
        if ($service === null) {
            return FailureType::ServiceNotConfigured;
        }

        return in_array($transaction->organisationId, $service->allowedOrganisations, true)
            ? null
            : FailureType::OrganisationRefused;
    }

    /**
     * The login flag `skipped` alone, or `verified` with the mapped claims the service releases. A
     * verified result without any released attribute is not delivered.
     *
     * @return non-empty-array<string, list<string>>|null
     */
    private static function attributes(
        Transaction $transaction,
        ?ProfileResult $result,
        JipConfiguration $configuration,
    ): ?array {
        $loginFlag = $configuration->attributes->loginFlag;
        if ($transaction->state === TransactionState::Skipped) {
            return [$loginFlag => [self::SKIPPED]];
        }

        $claims = $result?->verifiedClaims() ?? [];
        $released = [];
        foreach (($configuration->services[$transaction->serviceId] ?? null)->release ?? [] as $claim) {
            $mapping = $configuration->attributes->claims[$claim] ?? null;
            $values = $claims[$claim] ?? [];
            if ($mapping !== null && $values !== []) {
                $released[$mapping->attribute] = $values;
            }
        }

        return $released === [] ? null : [$loginFlag => [self::VERIFIED]] + $released;
    }

    private function fail(
        Transaction $transaction,
        string $failureType,
        bool $restartable,
        JipConfiguration $configuration,
    ): DeliveryOutcome {
        if (
            !$this->store->compareAndSet(
                $transaction->id,
                $transaction->state,
                $transaction->failed($failureType, $restartable),
                $this->clock->now(),
            )
        ) {
            return $this->lostRace($transaction, $configuration);
        }

        $this->logger->warning(
            'JIP result {log_id}: refused ({failure_type}) for service {service}, organisation {organisation},'
            . ' policy version {policy_version} at start and {policy_version_delivery} at delivery,'
            . ' EngineBlock request {eb_request_id}',
            ['log_id' => $transaction->logId, 'failure_type' => $failureType]
            + self::context($transaction, $configuration),
        );

        return DeliveryOutcome::forbidden();
    }

    /**
     * The consuming write was refused. When only the recheck's validity ended first, the unchanged
     * transaction fails like any failed recheck (design §13); otherwise another call won or it expired.
     */
    private function notConsumed(
        Transaction $transaction,
        ?DateTimeImmutable $validUntil,
        JipConfiguration $configuration,
    ): DeliveryOutcome {
        $current = $this->store->find($transaction->id);
        $now = $this->clock->now();
        if (
            $validUntil !== null && $now >= $validUntil
            && $current !== null && $current->state === $transaction->state && !$current->isExpired($now)
        ) {
            $type = FailureType::Expired;

            return $this->fail($transaction, $type->value, $type->isRestartable(), $configuration);
        }

        return $this->lostRace($transaction, $configuration);
    }

    /**
     * Another call changed the transaction, or it expired.
     */
    private function lostRace(Transaction $transaction, JipConfiguration $configuration): DeliveryOutcome
    {
        $current = $this->store->find($transaction->id);
        $now = $this->clock->now();
        if ($current?->state === TransactionState::Consumed) {
            return $this->refuseUnchanged($current, FailureType::AlreadyUsed, $configuration);
        }
        if ($transaction->isExpired($now) || ($current !== null && $current->isExpired($now))) {
            return $this->refuseUnchanged($current ?? $transaction, FailureType::Expired, $configuration);
        }
        $this->logger->warning('JIP result {log_id}: not consumed; the transaction changed or expired', [
            'log_id' => $transaction->logId,
        ]);

        return $current === null || $current->isExpired($now) || $current->state === TransactionState::Consumed
            ? DeliveryOutcome::notFound()
            : DeliveryOutcome::forbidden();
    }

    private function refuseUnchanged(
        Transaction $transaction,
        FailureType $type,
        JipConfiguration $configuration,
    ): DeliveryOutcome {
        $this->logger->warning(
            'JIP result {log_id}: refused ({failure_type}); transaction unchanged ({state})'
            . ' for service {service}, organisation {organisation},'
            . ' policy version {policy_version} at start and {policy_version_delivery} at delivery,'
            . ' EngineBlock request {eb_request_id}',
            ['log_id' => $transaction->logId, 'failure_type' => $type->value, 'state' => $transaction->state->value]
            + self::context($transaction, $configuration),
        );

        return DeliveryOutcome::notFound();
    }

    /**
     * @return array<string, string>
     */
    private static function context(Transaction $transaction, JipConfiguration $configuration): array
    {
        return [
            'policy_version_delivery' => ($configuration->services[$transaction->serviceId] ?? null)
                ->connectionPolicyVersion ?? '-',
        ] + LogFields::correlation($transaction);
    }
}
