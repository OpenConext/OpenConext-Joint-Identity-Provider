<?php

declare(strict_types=1);

namespace JointIdentityProvider\TestSp;

/**
 * Lines for the container's error log. They hold identifiers and fixed texts, never attribute values,
 * assertions or cookies (design §20).
 */
final class Log
{
    private const string SAML_ID = '/^[A-Za-z0-9_.:-]{1,128}\z/';

    public static function info(string $message): void
    {
        error_log('JIP test SP: ' . $message);
    }

    /**
     * A SAML ID from a message, or '-' when it could break a log line.
     */
    public static function samlId(?string $id): string
    {
        return $id !== null && preg_match(self::SAML_ID, $id) === 1 ? $id : '-';
    }
}
