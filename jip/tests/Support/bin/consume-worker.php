<?php

declare(strict_types=1);

// Consumes one skipped transaction at a shared start time; prints "consumed" or "refused".
// Usage: consume-worker.php <database path> <transaction id> <start time as microtime float>

use JointIdentityProvider\Core\Storage\SqliteTransactionStore;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use Symfony\Component\Clock\NativeClock;

require dirname(__DIR__, 3) . '/vendor/autoload.php';

$arguments = $_SERVER['argv'] ?? null;
if (!is_array($arguments) || count($arguments) !== 4) {
    fwrite(STDERR, "usage\n");
    exit(2);
}
[, $path, $id, $startAt] = array_map(static fn (mixed $value): string => is_string($value) ? $value : '', $arguments);

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

while (microtime(true) < (float) $startAt) {
    usleep(100);
}

echo $store->compareAndSet($id, TransactionState::Skipped, $consumed, new DateTimeImmutable()) ? 'consumed' : 'refused';
