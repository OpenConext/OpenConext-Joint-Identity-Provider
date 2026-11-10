<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Result;

use DateTimeImmutable;
use JointIdentityProvider\Core\EngineBlock\LogFields;
use JointIdentityProvider\Core\Transaction\FailureType;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Consumed takes precedence over expired. Refusals here never change the transaction.
 */
final readonly class TransactionRefusal
{
    public const string START_CORRELATION =
        ' policy version {policy_version} at start, EngineBlock request {eb_request_id}';

    public function __construct(
        #[Autowire(service: 'jip.logger')] private LoggerInterface $logger,
    ) {
    }

    public static function reason(Transaction $transaction, DateTimeImmutable $now): ?FailureType
    {
        return match (true) {
            $transaction->state === TransactionState::Consumed => FailureType::AlreadyUsed,
            $transaction->isExpired($now) => FailureType::Expired,
            default => null,
        };
    }

    /**
     * @param array<string, string> $correlationContext values for placeholders that $correlation adds
     */
    public function log(
        string $flow,
        Transaction $transaction,
        FailureType $type,
        string $correlation = self::START_CORRELATION,
        array $correlationContext = [],
    ): void {
        $this->logger->warning(
            'JIP {flow} {log_id}: refused ({failure_type}); transaction unchanged ({state})'
            . ' for service {service}, organisation {organisation},' . $correlation,
            [
                'flow' => $flow,
                'log_id' => $transaction->logId,
                'failure_type' => $type->value,
                'state' => $transaction->state->value,
            ] + $correlationContext + LogFields::correlation($transaction),
        );
    }
}
