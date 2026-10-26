<?php

declare(strict_types=1);

// Consumes one skipped transaction after a parent-controlled barrier; prints "consumed" or "refused".
// Usage: consume-worker.php <transaction id>; the test database comes from .env.test, as in the suite.

use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Tests\Support\TestDatabase;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\Dotenv\Dotenv;

require dirname(__DIR__, 3) . '/vendor/autoload.php';

$_SERVER['APP_ENV'] = 'test';
(new Dotenv())->bootEnv(dirname(__DIR__, 3) . '/.env');

$arguments = $_SERVER['argv'] ?? null;
if (!is_array($arguments) || count($arguments) !== 2) {
    fwrite(STDERR, "usage\n");
    exit(2);
}
$id = is_string($arguments[1]) ? $arguments[1] : '';

$store = TestDatabase::store(new NativeClock());
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
