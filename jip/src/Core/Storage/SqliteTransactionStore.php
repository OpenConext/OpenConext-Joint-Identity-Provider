<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Storage;

use Closure;
use DateTimeImmutable;
use InvalidArgumentException;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Core\Transaction\TransactionStore;
use PDO;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Throwable;

/**
 * The proof of concept's single-node transaction store (design §11, §13): one SQLite file. Every write runs
 * in a `BEGIN IMMEDIATE` transaction, so a compare-and-set reads and replaces the record under one write
 * lock, also across processes. Writes prune records past their deadline; callers treat them as expired.
 */
final class SqliteTransactionStore implements TransactionStore
{
    // SQLite's busy timeout; well within EngineBlock's call timeout.
    private const int BUSY_TIMEOUT_SECONDS = 2;

    private const string SCHEMA = <<<'SQL'
        CREATE TABLE IF NOT EXISTS jip_transactions (
            id TEXT PRIMARY KEY NOT NULL,
            log_id TEXT NOT NULL UNIQUE,
            oidc_state TEXT UNIQUE,
            deadline_us INTEGER NOT NULL,
            record TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS jip_transactions_deadline ON jip_transactions (deadline_us);
        SQL;

    private ?PDO $connection = null;

    public function __construct(
        private readonly string $path,
        private readonly ClockInterface $clock,
    ) {
    }

    public function add(Transaction $transaction): bool
    {
        if (!$transaction->state->isInitial()) {
            throw new InvalidArgumentException('A new transaction must start in pending, skipped or failed.');
        }

        return $this->write(function (PDO $db) use ($transaction): bool {
            $this->prune($db);

            $insert = $db->prepare(
                'INSERT OR IGNORE INTO jip_transactions (id, log_id, oidc_state, deadline_us, record)'
                . ' VALUES (?, ?, ?, ?, ?)',
            );
            $insert->execute([
                $transaction->id,
                $transaction->logId,
                $transaction->attempt?->oidcState,
                TransactionCodec::micros($transaction->deadline()),
                TransactionCodec::encode($transaction),
            ]);

            return $insert->rowCount() === 1;
        });
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

        return $this->write(function (PDO $db) use (
            $transactionId,
            $expectedState,
            $replacement,
            $now,
            $validUntil,
        ): bool {
            $this->prune($db);
            $current = $this->select($db, 'id', $transactionId);
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
        });
    }

    private function prune(PDO $db): void
    {
        $db->prepare('DELETE FROM jip_transactions WHERE deadline_us <= ?')
            ->execute([TransactionCodec::micros($this->clock->now())]);
    }

    /**
     * @param 'id'|'oidc_state' $column
     */
    private function select(PDO $db, string $column, string $value): ?Transaction
    {
        $statement = $db->prepare(sprintf('SELECT record FROM jip_transactions WHERE %s = ?', $column));
        $statement->execute([$value]);
        $record = $statement->fetchColumn();

        return is_string($record) ? TransactionCodec::decode($record) : null;
    }

    /**
     * @template T
     * @param Closure(PDO): T $operation
     * @return T
     */
    private function write(Closure $operation): mixed
    {
        $db = $this->connection();
        $db->exec('BEGIN IMMEDIATE');
        try {
            $result = $operation($db);
            $db->exec('COMMIT');

            return $result;
        } catch (Throwable $exception) {
            try {
                $db->exec('ROLLBACK');
            } catch (Throwable) {
                // SQLite already rolled back; the original exception explains why.
            }

            throw $exception;
        }
    }

    private function connection(): PDO
    {
        if ($this->connection !== null) {
            return $this->connection;
        }

        $directory = dirname($this->path);
        if (!is_dir($directory) && !@mkdir($directory, 0o750, true) && !is_dir($directory)) {
            throw new RuntimeException('Cannot create the directory of the transaction store.');
        }

        $db = new PDO('sqlite:' . $this->path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_TIMEOUT => self::BUSY_TIMEOUT_SECONDS,
        ]);
        $db->exec('PRAGMA secure_delete = ON');
        $db->exec(self::SCHEMA);

        return $this->connection = $db;
    }
}
