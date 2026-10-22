<?php

declare(strict_types=1);

namespace JointIdentityProvider\Devenv\Tests;

use JointIdentityProvider\Devenv\ManageHttpFailure;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

use function JointIdentityProvider\Devenv\pushToEngineBlock;

final class ManagePushTest extends TestCase
{
    private const string OIDC_ERROR = 'Error in push to OIDC (https://connect.dev.openconext.local/manage/connections)'
        . ' status 503 SERVICE_UNAVAILABLE and response <html><body><h1>503 Service Unavailable</h1>'
        . "\nNo server is available to handle this request.\n</body></html>\n";

    public static function setUpBeforeClass(): void
    {
        require_once dirname(__DIR__) . '/bin/_manage.php';
    }

    public function testSuccessfulPush(): void
    {
        self::assertTrue(pushToEngineBlock(static fn (): array => []));
    }

    public function testOnlyTheKnownOidcFailureIsTolerated(): void
    {
        self::assertFalse(pushToEngineBlock(static fn (): never => throw new ManageHttpFailure(
            'push failed',
            500,
            json_encode(['message' => self::OIDC_ERROR], JSON_THROW_ON_ERROR),
        )));
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function rejectedFailures(): iterable
    {
        yield 'EngineBlock push failure' => [500, json_encode([
            'message' => 'Error in push to EngineBlock status 503 SERVICE_UNAVAILABLE',
        ], JSON_THROW_ON_ERROR)];
        yield 'unknown backend response' => [500, '{"message":"unexpected failure"}'];
        yield 'invalid JSON' => [500, 'not json'];
        yield 'transport failure' => [0, ''];
        yield 'wrong HTTP status' => [503, json_encode(['message' => self::OIDC_ERROR], JSON_THROW_ON_ERROR)];
        yield 'different OIDC failure' => [500, json_encode([
            'message' => str_replace('503 SERVICE_UNAVAILABLE', '401 UNAUTHORIZED', self::OIDC_ERROR),
        ], JSON_THROW_ON_ERROR)];
        yield 'additional backend failure' => [500, json_encode([
            'message' => self::OIDC_ERROR,
            'engineBlockError' => 'failed',
        ], JSON_THROW_ON_ERROR)];
    }

    #[DataProvider('rejectedFailures')]
    public function testOtherHttpFailuresPropagate(int $status, string $body): void
    {
        $failure = new ManageHttpFailure('push failed', $status, $body);
        $this->expectExceptionObject($failure);

        pushToEngineBlock(static fn (): never => throw $failure);
    }

    public function testNonHttpFailuresPropagate(): void
    {
        $failure = new RuntimeException('push failed');
        $this->expectExceptionObject($failure);

        pushToEngineBlock(static fn (): never => throw $failure);
    }
}
