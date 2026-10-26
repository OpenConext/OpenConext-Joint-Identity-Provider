<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Storage;

use DateTimeImmutable;
use InvalidArgumentException;
use JointIdentityProvider\Core\Configuration\TransactionStoreConfiguration;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Core\Transaction\TransactionStore;
use PDO;
use PDOException;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Throwable;

/**
 * The shared transaction store (design §10, §13) on MariaDB 10.6. A compare-and-set reads the record with
 * SELECT ... FOR UPDATE and replaces it in the same InnoDB transaction, so the row lock serialises writers
 * across processes and nodes. Writes first prune records past their deadline; callers treat them as expired.
 */
final class MariaDbTransactionStore implements TransactionStore
{
    // Each connection, network read, statement and lock wait is bounded; not a whole-request deadline.
    private const int TIMEOUT_SECONDS = 2;
    private const int ER_DUP_ENTRY = 1062;

    // The binary no-pad collation compares identifiers byte for byte, trailing spaces included.
    private const string SCHEMA = <<<'SQL'
        CREATE TABLE IF NOT EXISTS jip_transactions (
            id VARCHAR(255) NOT NULL,
            log_id VARCHAR(255) NOT NULL,
            oidc_state VARCHAR(255) NULL,
            deadline_us BIGINT NOT NULL,
            record MEDIUMTEXT NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY jip_transactions_log_id (log_id),
            UNIQUE KEY jip_transactions_oidc_state (oidc_state),
            KEY jip_transactions_deadline (deadline_us)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin
        SQL;

    private ?PDO $connection = null;

    public function __construct(
        private readonly TransactionStoreConfiguration $configuration,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * Deployment-only initialization. Runtime connections need no DDL privileges.
     */
    public function initializeSchema(): void
    {
        $this->connection()->exec(self::SCHEMA);
    }

    public function checkAvailability(): void
    {
        // Check schema and SELECT access without reading records or modifying the store.
        $this->connection()->query('SELECT id FROM jip_transactions LIMIT 0');
    }

    public function add(Transaction $transaction): bool
    {
        if (!$transaction->state->isInitial()) {
            throw new InvalidArgumentException('A new transaction must start in pending, skipped or failed.');
        }

        $db = $this->connection();
        $this->prune($db);
        try {
            $db->prepare(
                'INSERT INTO jip_transactions (id, log_id, oidc_state, deadline_us, record) VALUES (?, ?, ?, ?, ?)',
            )->execute([
                $transaction->id,
                $transaction->logId,
                $transaction->attempt?->oidcState,
                TransactionCodec::micros($transaction->deadline()),
                TransactionCodec::encode($transaction),
            ]);
        } catch (PDOException $exception) {
            if (($exception->errorInfo[1] ?? null) === self::ER_DUP_ENTRY) {
                return false;
            }

            throw $exception;
        }

        return true;
    }

    public function find(string $transactionId): ?Transaction
    {
        return $this->select($this->connection(), 'id', $transactionId);
    }

    public function findByOidcState(string $oidcState): ?Transaction
    {
        return $this->select($this->connection(), 'oidc_state', $oidcState);
    }

    public function compareAndSet(
        string $transactionId,
        TransactionState $expectedState,
        Transaction $replacement,
        DateTimeImmutable $now,
        ?DateTimeImmutable $validUntil = null,
    ): bool {
        if ($replacement->id !== $transactionId) {
            throw new InvalidArgumentException('The replacement must carry the same transaction ID.');
        }

        $db = $this->connection();
        $this->prune($db);
        $db->beginTransaction();
        try {
            $replaced = $this->replace($db, $transactionId, $expectedState, $replacement, $now, $validUntil);
            $db->commit();

            return $replaced;
        } catch (Throwable $exception) {
            try {
                $db->rollBack();
            } catch (Throwable) {
                // The connection is gone and MariaDB rolled back; the original exception explains why.
            }

            throw $exception;
        }
    }

    private function replace(
        PDO $db,
        string $transactionId,
        TransactionState $expectedState,
        Transaction $replacement,
        DateTimeImmutable $now,
        ?DateTimeImmutable $validUntil,
    ): bool {
        $current = $this->select($db, 'id', $transactionId, forUpdate: true);
        $effectiveNow = max($now, $this->clock->now());
        if (
            $current === null || $current->state !== $expectedState || $current->isExpired($effectiveNow)
            || ($validUntil !== null && $effectiveNow >= $validUntil)
        ) {
            return false;
        }

        $current->assertCanBeReplacedBy($replacement);

        $db->prepare('UPDATE jip_transactions SET oidc_state = ?, deadline_us = ?, record = ? WHERE id = ?')
            ->execute([
                $replacement->attempt?->oidcState,
                TransactionCodec::micros($replacement->deadline()),
                TransactionCodec::encode($replacement),
                $transactionId,
            ]);

        return true;
    }

    private function prune(PDO $db): void
    {
        $db->prepare('DELETE FROM jip_transactions WHERE deadline_us <= ?')
            ->execute([TransactionCodec::micros($this->clock->now())]);
    }

    /**
     * @param 'id'|'oidc_state' $column
     */
    private function select(PDO $db, string $column, string $value, bool $forUpdate = false): ?Transaction
    {
        $statement = $db->prepare(sprintf(
            'SELECT record FROM jip_transactions WHERE %s = ?%s',
            $column,
            $forUpdate ? ' FOR UPDATE' : '',
        ));
        $statement->execute([$value]);
        $record = $statement->fetchColumn();

        return is_string($record) ? TransactionCodec::decode($record) : null;
    }

    private function connection(): PDO
    {
        if ($this->connection !== null) {
            return $this->connection;
        }

        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_TIMEOUT => self::TIMEOUT_SECONDS,
            PDO::ATTR_EMULATE_PREPARES => false,
        ] + TransactionStoreTls::options($this->configuration);

        // mysqlnd copies this setting into the new connection; restore the process default afterwards.
        $previousTimeout = ini_set('mysqlnd.net_read_timeout', (string) self::TIMEOUT_SECONDS);
        if ($previousTimeout === false) {
            throw new RuntimeException('The transaction store requires a configurable mysqlnd.net_read_timeout.');
        }
        try {
            $db = new PDO(
                $this->configuration->dsn(),
                $this->configuration->user,
                $this->configuration->password,
                $options,
            );
        } finally {
            ini_set('mysqlnd.net_read_timeout', $previousTimeout);
        }
        TransactionStoreTls::verify($db, $this->configuration);
        $db->exec(sprintf(
            "SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION', "
            . 'SESSION innodb_lock_wait_timeout = %1$d, SESSION lock_wait_timeout = %1$d, '
            . 'SESSION max_statement_time = %1$d',
            self::TIMEOUT_SECONDS,
        ));
        // Read committed takes no gap locks, so concurrent prunes and inserts cannot deadlock on them.
        $db->exec('SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED');

        return $this->connection = $db;
    }
}
