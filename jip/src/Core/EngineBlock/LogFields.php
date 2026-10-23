<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\EngineBlock;

use JointIdentityProvider\Core\Transaction\Transaction;

/**
 * Log values derived from EngineBlock's input (design §20). They hold no credential.
 */
final class LogFields
{
    private const string LOGGABLE_REQUEST_ID = '/^[A-Za-z0-9_.:-]{1,128}\z/';

    /**
     * The start-side correlation fields shared by every transaction log (design §20).
     *
     * @return array{service: string, organisation: string, policy_version: string, eb_request_id: string}
     */
    public static function correlation(Transaction $transaction): array
    {
        return [
            'service' => self::entityId($transaction->serviceId),
            'organisation' => self::entityId($transaction->organisationId),
            'policy_version' => $transaction->connectionPolicyVersionAtStart,
            'eb_request_id' => self::engineBlockRequestId($transaction->returnUrl),
        ];
    }

    /**
     * EngineBlock's request ID, taken from the return URL; '-' when it is absent or not loggable.
     */
    public static function engineBlockRequestId(string $returnUrl): string
    {
        parse_str((string) parse_url($returnUrl, PHP_URL_QUERY), $query);
        $id = $query['ID'] ?? null;

        return is_string($id) && preg_match(self::LOGGABLE_REQUEST_ID, $id) === 1 ? $id : '-';
    }

    /**
     * Entity IDs come from EngineBlock; anything that could break a log line is replaced.
     */
    public static function entityId(string $entityId): string
    {
        return preg_match('/^[\x21-\x7E]{1,512}\z/', $entityId) === 1 ? $entityId : '[unprintable]';
    }
}
