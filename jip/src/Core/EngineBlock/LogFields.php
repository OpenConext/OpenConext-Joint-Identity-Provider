<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\EngineBlock;

/**
 * Log values derived from EngineBlock's input (design §20). They hold no credential.
 */
final class LogFields
{
    private const string LOGGABLE_REQUEST_ID = '/^[A-Za-z0-9_.:-]{1,128}$/';

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
        return preg_match('/^[\x21-\x7E]{1,512}$/', $entityId) === 1 ? $entityId : '[unprintable]';
    }
}
