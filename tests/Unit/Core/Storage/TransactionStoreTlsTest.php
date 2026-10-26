<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Core\Storage;

use JointIdentityProvider\Core\Configuration\TransactionStoreConfiguration;
use JointIdentityProvider\Core\Storage\TransactionStoreTls;
use PDO;
use Pdo\Mysql;
use PDOStatement;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class TransactionStoreTlsTest extends TestCase
{
    public function test_a_configured_ca_requires_server_certificate_verification(): void
    {
        self::assertSame([
            Mysql::ATTR_SSL_CA => '/etc/jip/db-ca.pem',
            Mysql::ATTR_SSL_VERIFY_SERVER_CERT => true,
        ], TransactionStoreTls::options(self::configuration('/etc/jip/db-ca.pem')));
    }

    /** @return iterable<string, array{string|false}> */
    public static function missingCiphers(): iterable
    {
        yield 'an empty cipher' => [''];
        yield 'a missing status row' => [false];
    }

    #[DataProvider('missingCiphers')]
    public function test_a_tls_required_session_without_a_cipher_is_refused(string|false $cipher): void
    {
        $statement = self::createMock(PDOStatement::class);
        $statement->expects(self::once())->method('fetchColumn')->with(1)->willReturn($cipher);
        $db = self::createMock(PDO::class);
        $db->expects(self::once())->method('query')->with("SHOW SESSION STATUS LIKE 'Ssl_cipher'")->willReturn($statement);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The transaction store requires an encrypted TLS connection.');

        TransactionStoreTls::verify($db, self::configuration('/etc/jip/db-ca.pem'));
    }

    public function test_an_encrypted_session_passes(): void
    {
        $statement = self::createMock(PDOStatement::class);
        $statement->expects(self::once())->method('fetchColumn')->with(1)->willReturn('TLS_AES_256_GCM_SHA384');
        $db = self::createMock(PDO::class);
        $db->expects(self::once())->method('query')->with("SHOW SESSION STATUS LIKE 'Ssl_cipher'")->willReturn($statement);

        TransactionStoreTls::verify($db, self::configuration('/etc/jip/db-ca.pem'));
    }

    public function test_mock_without_a_ca_does_not_request_tls(): void
    {
        $configuration = self::configuration(null);
        self::assertSame([], TransactionStoreTls::options($configuration));
        $db = self::createMock(PDO::class);
        $db->expects(self::never())->method('query');

        TransactionStoreTls::verify($db, $configuration);
    }

    private static function configuration(?string $tlsCa): TransactionStoreConfiguration
    {
        return new TransactionStoreConfiguration('db.example', 3306, 'jip', 'jip', 'test-password', $tlsCa);
    }
}
