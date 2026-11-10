<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Result;

use DateTimeImmutable;
use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Core\EngineBlock\LogFields;
use JointIdentityProvider\Core\Transaction\FailureType;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use Psr\Log\LoggerInterface;

/**
 * Consumed takes precedence over expired. Refusals here never change the transaction.
 */
final readonly class TransactionRefusal
{
    public function __construct(private LoggerInterface $logger)
    {
    }

    public static function reason(Transaction $transaction, DateTimeImmutable $now): ?FailureType
    {
        return match (true) {
            $transaction->state === TransactionState::Consumed => FailureType::AlreadyUsed,
            $transaction->isExpired($now) => FailureType::Expired,
            default => null,
        };
    }

    public function log(
        string $flow,
        Transaction $transaction,
        FailureType $type,
        ?JipConfiguration $deliveryConfiguration = null,
    ): void {
        $suffix = $deliveryConfiguration === null
            ? ' policy version {policy_version} at start, EngineBlock request {eb_request_id}'
            : ' policy version {policy_version} at start and {policy_version_delivery} at delivery,'
                . ' EngineBlock request {eb_request_id}';
        $context = [
            'flow' => $flow,
            'log_id' => $transaction->logId,
            'failure_type' => $type->value,
            'state' => $transaction->state->value,
        ] + LogFields::correlation($transaction);
        if ($deliveryConfiguration !== null) {
            $context['policy_version_delivery'] = ($deliveryConfiguration->services[$transaction->serviceId] ?? null)
                ->connectionPolicyVersion ?? '-';
        }

        $this->logger->warning(
            'JIP {flow} {log_id}: refused ({failure_type}); transaction unchanged ({state})'
            . ' for service {service}, organisation {organisation},' . $suffix,
            $context,
        );
    }
}
