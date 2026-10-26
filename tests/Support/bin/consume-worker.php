<?php

declare(strict_types=1);

// Consumes one skipped transaction after a parent-controlled barrier; prints "consumed" or "refused".
// Usage: consume-worker.php <database path> <transaction id>

use JointIdentityProvider\Core\Storage\SqliteTransactionStore;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use Symfony\Component\Clock\NativeClock;

require dirname(__DIR__, 3) . '/vendor/autoload.php';

$arguments = $_SERVER['argv'] ?? null;
if (!is_array($arguments) || count($arguments) !== 3) {
    fwrite(STDERR, "usage\n");
    exit(2);
}
[, $path, $id] = array_map(static fn (mixed $value): string => is_string($value) ? $value : '', $arguments);

$store = new SqliteTransactionStore($path, new NativeClock());
$current = $store->find($id) ?? throw new RuntimeException('no transaction');
$consumed = new Transaction(
    $current->id,
    $current->logId,
    $current->serviceId,
    $current->organisationId,
    $current->userId,
    $current->connectionPolicyVersionAtStart,
    $current->organisationBindingValue,
    $current->returnUrl,
    $current->transactionDeadline,
    TransactionState::Consumed,
    resultDeadline: $current->resultDeadline,
);

fwrite(STDOUT, "ready\n");
fflush(STDOUT);
if (fgets(STDIN) !== "go\n") {
    exit(1);
}

echo $store->compareAndSet($id, TransactionState::Skipped, $consumed, new DateTimeImmutable()) ? 'consumed' : 'refused';
