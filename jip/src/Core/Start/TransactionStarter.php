<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Start;

use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Core\Configuration\ServicePolicy;
use JointIdentityProvider\Core\EngineBlock\LogFields;
use JointIdentityProvider\Core\EngineBlock\ReturnUrl;
use JointIdentityProvider\Core\Transaction\FailureType;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Core\Transaction\TransactionStore;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Opens a transaction for EngineBlock's start call (design §4, §13). Makes no outgoing request.
 */
final readonly class TransactionStarter
{
    private const int MAX_ADD_ATTEMPTS = 3;
    private const string TRANSACTION_ID = '/^[A-Za-z0-9_-]{43}$/';
    private const string LOG_ID = '/^[0-9a-f]{16}$/';

    public function __construct(
        private TransactionStore $store,
        private IdentifierGenerator $identifiers,
        private ClockInterface $clock,
        private LoggerInterface $logger,
    ) {
    }

    public function start(StartRequest $request, JipConfiguration $configuration): StartOutcome
    {
        $service = $configuration->services[$request->serviceId] ?? null;
        if ($service === null) {
            return $this->refuse(StartOutcome::UNKNOWN_SERVICE, $request);
        }

        if (!ReturnUrl::isValid($request->continueUrl, $configuration->engineBlock->returnUrlPrefix)) {
            return $this->refuse(StartOutcome::INVALID_RETURN_URL, $request);
        }

        [$state, $failure] = self::decide($request, $service, $configuration->attributes->reservedPrefix);

        $now = $this->clock->now();
        $deadline = $now->modify(sprintf('+%d seconds', $configuration->transactions->lifetimeSeconds));

        for ($attempt = 0; $attempt < self::MAX_ADD_ATTEMPTS; $attempt++) {
            $id = $this->identifiers->transactionId();
            $logId = $this->identifiers->logId();
            if (preg_match(self::TRANSACTION_ID, $id) !== 1 || preg_match(self::LOG_ID, $logId) !== 1) {
                return $this->refuse(StartOutcome::NOT_CREATED, $request);
            }

            $transaction = new Transaction(
                $id,
                $logId,
                $service->serviceId,
                $request->issuerId,
                $request->userId,
                $service->connectionPolicyVersion,
                $state === TransactionState::Pending ? $request->binding->value : '',
                $request->continueUrl,
                $deadline,
                $state,
                resultDeadline: $state === TransactionState::Skipped ? $deadline : null,
                failureType: $failure?->value,
            );

            try {
                $added = $this->store->add($transaction);
            } catch (Throwable $exception) {
                $this->logger->error('JIP could not store a new transaction: {exception_class}', [
                    'exception_class' => $exception::class,
                ]);

                return $this->refuse(StartOutcome::NOT_CREATED, $request);
            }

            if ($added) {
                $this->logStart($transaction);

                return StartOutcome::created($transaction);
            }
        }

        return $this->refuse(StartOutcome::NOT_CREATED, $request);
    }

    /**
     * In this order: organisation policy, reserved names, binding attribute (design §13).
     *
     * @return array{TransactionState, ?FailureType}
     */
    private static function decide(StartRequest $request, ServicePolicy $service, string $reservedPrefix): array
    {
        if (!in_array($request->issuerId, $service->allowedOrganisations, true)) {
            return [TransactionState::Failed, FailureType::OrganisationRefused];
        }

        foreach ($request->attributeNames as $name) {
            if (str_starts_with($name, $reservedPrefix)) {
                return [TransactionState::Failed, FailureType::ReservedAttribute];
            }
        }

        return match ($request->binding->status) {
            BindingStatus::Malformed => [TransactionState::Failed, FailureType::MalformedBinding],
            BindingStatus::Absent => [TransactionState::Skipped, null],
            BindingStatus::Single => [TransactionState::Pending, null],
        };
    }

    private function refuse(string $reason, StartRequest $request): StartOutcome
    {
        $this->logger->warning(
            'JIP start refused ({reason}) for service {service}, EngineBlock request {eb_request_id}',
            [
                'reason' => $reason,
                'service' => LogFields::entityId($request->serviceId),
                'eb_request_id' => LogFields::engineBlockRequestId($request->continueUrl),
            ],
        );

        return StartOutcome::error($reason);
    }

    private function logStart(Transaction $transaction): void
    {
        $this->logger->info(
            'JIP start {log_id}: {state}{failure_type} for service {service}, organisation {organisation},'
            . ' policy version {policy_version}, EngineBlock request {eb_request_id}',
            [
                'log_id' => $transaction->logId,
                'state' => $transaction->state->value,
                'failure_type' => $transaction->failureType === null ? '' : ' (' . $transaction->failureType . ')',
                'service' => $transaction->serviceId,
                'organisation' => LogFields::entityId($transaction->organisationId),
                'policy_version' => $transaction->connectionPolicyVersionAtStart,
                'eb_request_id' => LogFields::engineBlockRequestId($transaction->returnUrl),
            ],
        );
    }
}
