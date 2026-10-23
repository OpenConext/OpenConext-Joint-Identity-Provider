<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Browser;

use DateTimeImmutable;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Oidc\Configuration\ClientConfiguration;
use SensitiveParameter;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * Each transaction's own browser cookie, named after its log ID (design §13), so logins in two tabs do
 * not interfere. It is sent only to the callback and lives until the transaction deadline.
 */
final class TransactionCookie
{
    private const string PREFIX = '__Secure-jip_tx_';

    public static function name(Transaction $transaction): string
    {
        return self::PREFIX . $transaction->logId;
    }

    public static function create(Transaction $transaction, #[SensitiveParameter] string $value): Cookie
    {
        return self::cookie($transaction, $value, $transaction->transactionDeadline);
    }

    public static function clear(Transaction $transaction): Cookie
    {
        return self::cookie($transaction, '', new DateTimeImmutable('@1'));
    }

    private static function cookie(
        Transaction $transaction,
        #[SensitiveParameter] string $value,
        DateTimeImmutable $expires,
    ): Cookie {
        return Cookie::create(self::name($transaction))
            ->withValue($value)
            ->withExpires($expires)
            ->withPath(ClientConfiguration::CALLBACK_PATH)
            ->withSecure(true)
            ->withHttpOnly(true)
            ->withSameSite(Cookie::SAMESITE_LAX);
    }
}
