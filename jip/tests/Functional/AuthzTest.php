<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Functional;

use JointIdentityProvider\Core\Storage\SqliteTransactionStore;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use JointIdentityProvider\Tests\Support\ConfigurationFixture as Fixture;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Clock\NativeClock;

/**
 * POST /authz as EngineBlock calls it (design §12, §13).
 */
final class AuthzTest extends WebTestCase
{
    private const string BINDING = 'urn:mace:govroam.nl:attribute-def:organisation-dezi-nummer';
    private const string RETURN_URL = 'https://engine.dev.openconext.local/authentication/idp/process-sraminterrupt?ID=_8f3c';

    private Fixture $fixture;
    private KernelBrowser $client;

    protected function setUp(): void
    {
        $this->fixture = new Fixture();
        Fixture::setEnv('EB_API_TOKEN', Fixture::API_TOKEN);
        Fixture::setEnv('CONNECTOR_ENVIRONMENT', 'mock');
        Fixture::setEnv('JIP_CONFIG_FILE', $this->fixture->writeConfiguration($this->fixture->mockConfiguration()));
        $this->client = self::createClient();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        Fixture::setEnv('EB_API_TOKEN', null);
        Fixture::setEnv('JIP_CONFIG_FILE', null);
        $this->fixture->remove();
    }

    public function test_an_account_with_a_number_gets_interrupt_with_a_nonce_for_a_pending_transaction(): void
    {
        $body = $this->start([self::BINDING => ['123456789']]);

        self::assertResponseStatusCodeSame(200);
        self::assertResponseHeaderSame('Content-Type', 'application/json');
        self::assertResponseHeaderSame('Cache-Control', 'no-store, private');
        self::assertSame(['msg', 'nonce', 'message'], array_keys($body));
        self::assertSame('interrupt', $body['msg']);
        self::assertSame('DEZI_LOGIN_REQUIRED', $body['message']);
        self::assertSame(TransactionState::Pending, $this->stored($body)->state);
    }

    public function test_an_account_without_a_number_gets_interrupt_for_a_skipped_transaction(): void
    {
        $body = $this->start(['urn:mace:dir:attribute-def:mail' => ['j.doe@ggd.example.nl']]);

        self::assertSame('interrupt', $body['msg']);
        self::assertSame('DEZI_SKIPPED', $body['message']);
        self::assertSame(TransactionState::Skipped, $this->stored($body)->state);
    }

    public function test_a_failed_check_still_gets_interrupt_with_a_nonce(): void
    {
        $body = $this->start([self::BINDING => ['1', '2']]);

        self::assertSame(['msg', 'nonce'], array_keys($body));
        self::assertSame('interrupt', $body['msg']);
        $transaction = $this->stored($body);
        self::assertSame(TransactionState::Failed, $transaction->state);
        self::assertSame('malformed_binding', $transaction->failureType);
    }

    public function test_an_organisation_that_is_not_allowed_gets_a_failed_transaction(): void
    {
        $body = $this->start([], ['issuer_id' => 'http://mock-idp2']);

        self::assertSame('organisation_refused', $this->stored($body)->failureType);
    }

    public function test_a_numeric_attribute_name_is_accepted_as_a_json_object_key(): void
    {
        $body = $this->start([], ['attributes' => (object) ['1' => ['ignored'], self::BINDING => ['123456789']]]);

        self::assertResponseStatusCodeSame(200);
        self::assertSame(TransactionState::Pending, $this->stored($body)->state);
    }

    public function test_each_start_gets_its_own_nonce(): void
    {
        $first = $this->start([]);
        $second = $this->start([]);

        self::assertNotSame($first['nonce'], $second['nonce']);
    }

    public function test_an_unknown_service_gets_error(): void
    {
        $body = $this->start([], ['service_id' => 'https://unknown.example/metadata']);

        self::assertResponseStatusCodeSame(200);
        self::assertSame(['msg' => 'error'], $body);
    }

    public function test_a_return_url_outside_engineblock_gets_error(): void
    {
        $body = $this->start([], ['continue_url' => 'https://evil.example/process-sraminterrupt?ID=_1']);

        self::assertSame(['msg' => 'error'], $body);
    }

    public function test_a_correct_authorization_without_authentication_is_accepted(): void
    {
        $this->post(json_encode(self::payload([]), JSON_THROW_ON_ERROR), ['HTTP_AUTHORIZATION' => Fixture::API_TOKEN]);

        self::assertResponseStatusCodeSame(200);
    }

    /**
     * @param array<string, string> $headers
     */
    #[DataProvider('refusedTokens')]
    public function test_the_raw_authorization_token_is_required(array $headers): void
    {
        $this->post(json_encode(self::payload([]), JSON_THROW_ON_ERROR), $headers);

        self::assertResponseStatusCodeSame(401);
        self::assertSame('{"msg":"error"}', $this->client->getResponse()->getContent());
        self::assertFileDoesNotExist($this->fixture->storePath());
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function refusedTokens(): iterable
    {
        yield 'no headers' => [[]];
        yield 'a correct Authentication and no Authorization' => [['HTTP_AUTHENTICATION' => Fixture::API_TOKEN]];
        yield 'a wrong Authorization and a correct Authentication' => [[
            'HTTP_AUTHORIZATION' => 'wrong-token-0123456789abcdef0123456789',
            'HTTP_AUTHENTICATION' => Fixture::API_TOKEN,
        ]];
        yield 'a Bearer prefix' => [['HTTP_AUTHORIZATION' => 'Bearer ' . Fixture::API_TOKEN]];
        yield 'a token with trailing text' => [['HTTP_AUTHORIZATION' => Fixture::API_TOKEN . 'x']];
        yield 'a prefix of the token' => [['HTTP_AUTHORIZATION' => substr(Fixture::API_TOKEN, 0, -1)]];
    }

    /**
     * @param array<string, mixed>|string $payload
     */
    #[DataProvider('malformedRequests')]
    public function test_a_malformed_request_is_refused(array|string $payload): void
    {
        $this->post(is_string($payload) ? $payload : json_encode($payload, JSON_THROW_ON_ERROR), self::headers());

        self::assertResponseStatusCodeSame(400);
        self::assertSame('{"msg":"error"}', $this->client->getResponse()->getContent());
        self::assertFileDoesNotExist($this->fixture->storePath());
    }

    /**
     * @return iterable<string, array{array<string, mixed>|string}>
     */
    public static function malformedRequests(): iterable
    {
        yield 'not JSON' => ['user_id='];
        yield 'a JSON string' => ['"x"'];
        yield 'no attributes, as from EngineBlock 7.2.0' => [self::without(self::payload([]), 'attributes')];
        yield 'attributes as a list of values' => [['attributes' => ['123456789']] + self::payload([])];
        yield 'attributes as a string' => [['attributes' => 'x'] + self::payload([])];
        yield 'no user_id' => [self::without(self::payload([]), 'user_id')];
        yield 'an empty continue_url' => [['continue_url' => ''] + self::payload([])];
        yield 'no service_id' => [self::without(self::payload([]), 'service_id')];
        yield 'an integer issuer_id' => [['issuer_id' => 1] + self::payload([])];
    }

    #[DataProvider('emptyAttributes')]
    public function test_empty_attributes_as_a_json_list_or_object_are_no_attributes(string $json): void
    {
        $payload = json_encode(self::without(self::payload([]), 'attributes'), JSON_THROW_ON_ERROR);
        $this->post(substr($payload, 0, -1) . ',"attributes":' . $json . '}', self::headers());

        self::assertResponseStatusCodeSame(200);
        self::assertSame(TransactionState::Skipped, $this->stored(self::decode())->state);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function emptyAttributes(): iterable
    {
        yield 'list, as EngineBlock encodes an empty array' => ['[]'];
        yield 'object' => ['{}'];
    }

    public function test_get_is_not_allowed(): void
    {
        $this->client->request('GET', '/authz', server: self::headers());

        self::assertResponseStatusCodeSame(405);
    }

    public function test_unrelated_start_request_values_are_not_stored(): void
    {
        $body = $this->start(
            [
                self::BINDING => ['123456789'],
                'urn:mace:dir:attribute-def:mail' => ['secret-mail@example.nl'],
                'urn:mace:dir:attribute-def:cn' => ['Secret Name'],
            ],
            ['eppn' => 'secret-eppn@example.nl', 'email' => ['secret-email@example.nl'], 'external_subject_id' => 'secret-subject'],
        );

        self::assertSame('interrupt', $body['msg']);
        $database = (string) file_get_contents($this->fixture->storePath());
        self::assertStringContainsString('123456789', $database);
        foreach (['secret-mail', 'Secret Name', 'secret-eppn', 'secret-email', 'secret-subject', 'urn:mace:dir:attribute-def'] as $value) {
            self::assertStringNotContainsString($value, $database);
        }
    }

    /**
     * @param array<string, mixed> $attributes
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function start(array $attributes, array $overrides = []): array
    {
        $this->post(json_encode($overrides + self::payload($attributes), JSON_THROW_ON_ERROR), self::headers());

        return self::decode();
    }

    /**
     * @param array<string, string> $server
     */
    private function post(string $content, array $server): void
    {
        $this->client->request('POST', '/authz', server: $server + ['CONTENT_TYPE' => 'application/json'], content: $content);
    }

    /**
     * @return array<string, mixed>
     */
    private function decode(): array
    {
        $body = json_decode((string) $this->client->getResponse()->getContent(), true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($body);

        /** @var array<string, mixed> $body */
        return $body;
    }

    /**
     * @param array<string, mixed> $body
     */
    private function stored(array $body): Transaction
    {
        $nonce = $body['nonce'] ?? null;
        self::assertIsString($nonce);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $nonce);
        $transaction = new SqliteTransactionStore($this->fixture->storePath(), new NativeClock())->find($nonce);
        self::assertNotNull($transaction);

        return $transaction;
    }

    /**
     * @return array<string, string>
     */
    private static function headers(): array
    {
        return ['HTTP_AUTHORIZATION' => Fixture::API_TOKEN, 'HTTP_AUTHENTICATION' => Fixture::API_TOKEN];
    }

    /**
     * @param array<string, mixed> $attributes
     * @return array<string, mixed>
     */
    private static function payload(array $attributes): array
    {
        return [
            'user_id' => 'urn:collab:person:ggd.example.nl:jdoe',
            'eppn' => 'jdoe@ggd.example.nl',
            'external_subject_id' => '',
            'email' => ['j.doe@ggd.example.nl'],
            'continue_url' => self::RETURN_URL,
            'service_id' => Fixture::SERVICE,
            'issuer_id' => 'http://mock-idp',
            'attributes' => $attributes,
        ];
    }

    /**
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    private static function without(array $payload, string $key): array
    {
        unset($payload[$key]);

        return $payload;
    }
}
