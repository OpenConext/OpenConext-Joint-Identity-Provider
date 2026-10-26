<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Storage;

use JointIdentityProvider\Core\Configuration\TransactionStoreConfiguration;
use PDO;
use Pdo\Mysql;
use RuntimeException;

/**
 * TLS policy shared by runtime connections, deployment initialization and readiness checks.
 */
final class TransactionStoreTls
{
    /**
     * @return array<int, string|bool>
     */
    public static function options(TransactionStoreConfiguration $configuration): array
    {
        return $configuration->tlsCa === null ? [] : [
            Mysql::ATTR_SSL_CA => $configuration->tlsCa,
            Mysql::ATTR_SSL_VERIFY_SERVER_CERT => true,
        ];
    }

    public static function verify(PDO $db, TransactionStoreConfiguration $configuration): void
    {
        if ($configuration->tlsCa === null) {
            return;
        }

        $status = $db->query("SHOW SESSION STATUS LIKE 'Ssl_cipher'");
        $cipher = $status === false ? false : $status->fetchColumn(1);
        if (!is_string($cipher) || $cipher === '') {
            throw new RuntimeException('The transaction store requires an encrypted TLS connection.');
        }
    }
}
