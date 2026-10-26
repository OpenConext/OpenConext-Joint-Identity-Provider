<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Core\EngineBlock;

use DateTimeImmutable;
use JointIdentityProvider\Core\EngineBlock\LogFields;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LogFieldsTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string, string, string, string, string}>
     */
    public static function identifiers(): iterable
    {
        yield 'printable entity IDs and request ID' => [
            'https://sp.example/saml/metadata', 'https://idp.example', '_request-1',
            'https://sp.example/saml/metadata', 'https://idp.example', '_request-1',
        ];
        yield 'log injection in entity IDs' => [
            "https://sp.example\nforged outcome", "https://idp.example\rforged outcome", '_request-1',
            '[unprintable]', '[unprintable]', '_request-1',
        ];
        yield 'log injection in request ID' => [
            'https://sp.example', 'https://idp.example', "_request\nforged outcome",
            'https://sp.example', 'https://idp.example', '-',
        ];
        yield 'trailing newline in every identifier' => [
            "https://sp.example\n", "https://idp.example\n", "_request\n",
            '[unprintable]', '[unprintable]', '-',
        ];
        yield 'overlong identifiers' => [
            'https://sp.example/' . str_repeat('x', 512), 'https://idp.example', str_repeat('x', 129),
            '[unprintable]', 'https://idp.example', '-',
        ];
    }

    #[DataProvider('identifiers')]
    public function testCorrelationSanitizesInputAndExcludesCredentials(
        string $service,
        string $organisation,
        string $requestId,
        string $loggedService,
        string $loggedOrganisation,
        string $loggedRequestId,
    ): void {
        $transaction = new Transaction(
            'secret-transaction-nonce',
            '0123456789abcdef',
            $service,
            $organisation,
            'private-user-id',
            'approved-policy-1',
            'private-binding',
            'https://engine.example/return?' . http_build_query(['ID' => $requestId, 'token' => 'secret-token']),
            new DateTimeImmutable('+10 minutes'),
            TransactionState::Pending,
        );

        self::assertSame([
            'service' => $loggedService,
            'organisation' => $loggedOrganisation,
            'policy_version' => 'approved-policy-1',
            'eb_request_id' => $loggedRequestId,
        ], LogFields::correlation($transaction));
    }
}
