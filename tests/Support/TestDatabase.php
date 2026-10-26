<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Support;

use JointIdentityProvider\Core\Configuration\TransactionStoreConfiguration;
use JointIdentityProvider\Core\Storage\MariaDbTransactionStore;
use PDO;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Symfony\Component\Clock\NativeClock;

/**
 * The MariaDB database the test suite owns (JIP_TEST_DATABASE_* in .env.test). It holds test data only:
 * reset() drops and initializes JIP's table before each test.
 */
final class TestDatabase
{
    public static function configuration(): TransactionStoreConfiguration
    {
        $port = self::env('JIP_TEST_DATABASE_PORT');

        return new TransactionStoreConfiguration(
            self::env('JIP_TEST_DATABASE_HOST'),
            ctype_digit($port) ? (int) $port : throw new RuntimeException('JIP_TEST_DATABASE_PORT is not a number.'),
            self::env('JIP_TEST_DATABASE_NAME'),
            self::env('JIP_TEST_DATABASE_USER'),
            self::env('JIP_TEST_DATABASE_PASSWORD'),
        );
    }

    /**
     * The `transactions.store` block of a JIP configuration file.
     *
     * @return array{host: string, port: int, database: string, user: string, password: string}
     */
    public static function storeSettings(): array
    {
        $configuration = self::configuration();

        return [
            'host' => $configuration->host,
            'port' => $configuration->port,
            'database' => $configuration->database,
            'user' => $configuration->user,
            'password' => $configuration->password,
        ];
    }

    public static function store(ClockInterface $clock): MariaDbTransactionStore
    {
        return new MariaDbTransactionStore(self::configuration(), $clock);
    }

    public static function reset(): void
    {
        self::connection()->exec('DROP TABLE IF EXISTS jip_transactions');
        self::store(new NativeClock())->initializeSchema();
    }

    public static function tableExists(): bool
    {
        $statement = self::connection()->query("SHOW TABLES LIKE 'jip_transactions'");

        return $statement !== false && $statement->fetchColumn() !== false;
    }

    public static function rowCount(): int
    {
        if (!self::tableExists()) {
            return 0;
        }

        $statement = self::connection()->query('SELECT COUNT(*) FROM jip_transactions');
        $count = $statement === false ? false : $statement->fetchColumn();

        return is_numeric($count) ? (int) $count : -1;
    }

    /**
     * Every stored value, for checks that something was or was not persisted.
     */
    public static function contents(): string
    {
        $statement = self::connection()->query('SELECT * FROM jip_transactions');
        $rows = $statement === false ? [] : $statement->fetchAll(PDO::FETCH_NUM);

        return json_encode($rows, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    private static function connection(): PDO
    {
        $configuration = self::configuration();

        return new PDO($configuration->dsn(), $configuration->user, $configuration->password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
    }

    private static function env(string $name): string
    {
        $value = $_SERVER[$name] ?? $_ENV[$name] ?? getenv($name);

        return is_string($value) && $value !== ''
            ? $value
            : throw new RuntimeException(sprintf('%s is not set; see .env.test.', $name));
    }
}
