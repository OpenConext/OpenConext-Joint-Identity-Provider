<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Core\Configuration;

use Closure;
use JointIdentityProvider\Core\Configuration\Environment;
use JointIdentityProvider\Core\Configuration\InvalidConfiguration;
use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Oidc\Configuration\ClientAuthentication;
use JointIdentityProvider\Profile\Dezi\DeziProfileConfiguration;
use JointIdentityProvider\Tests\Support\ConfigurationFixture as Fixture;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * The startup checks of design §17, each with a passing and a failing case (design §18 "Startup").
 * Every case starts from the committed config/jip/mock.yaml.
 */
final class ConfigurationLoaderTest extends TestCase
{
    private const string SERVICE = "services['" . Fixture::SERVICE . "']";
    private const array SERVICE_PATH = ['services', Fixture::SERVICE];
    private const array CLIENT_PATH = ['provider', 'clients', 'ggd'];
    private const array DECRYPTION_KEY_PATH = ['provider', 'clients', 'ggd', 'decryption_keys', 0];
    private const array SIGNING_KEY_PATH = ['provider', 'clients', 'ggd', 'signing_key'];
    private const string PREFIX = 'urn:mace:govroam.nl:attribute-def:dezi:';

    private Fixture $fixture;

    protected function setUp(): void
    {
        $this->fixture = new Fixture();
        Fixture::setEnv('EB_API_TOKEN', Fixture::API_TOKEN);
        Fixture::setEnv('JIP_DATABASE_PASSWORD', 'database-password');
    }

    protected function tearDown(): void
    {
        Fixture::setEnv('EB_API_TOKEN', null);
        Fixture::setEnv('JIP_DATABASE_PASSWORD', null);
        Fixture::setEnv('JIP_TEST_PLACEHOLDER', null);
        $this->fixture->remove();
    }

    public function test_environment_overrides_restore_each_original_source(): void
    {
        $name = 'JIP_TEST_ENV_RESTORE';
        $server = array_intersect_key($_SERVER, [$name => true]);
        $environment = array_intersect_key($_ENV, [$name => true]);
        $process = getenv($name);
        try {
            $_SERVER[$name] = 'original-server';
            $_ENV[$name] = 'original-env';
            putenv($name . '=original-process');
            Fixture::setEnv($name, 'first');
            Fixture::setEnv($name, 'second');
            Fixture::setEnv($name, null);
            self::assertSame('original-server', $_SERVER[$name]);
            self::assertSame('original-env', $_ENV[$name]);
            self::assertSame('original-process', getenv($name));

            unset($_SERVER[$name], $_ENV[$name]);
            putenv($name);
            Fixture::setEnv($name, 'temporary');
            Fixture::setEnv($name, null);
            self::assertArrayNotHasKey($name, $_SERVER);
            self::assertArrayNotHasKey($name, $_ENV);
            self::assertFalse(getenv($name));
        } finally {
            Fixture::setEnv($name, null);
            unset($_SERVER[$name], $_ENV[$name]);
            $_SERVER += $server;
            $_ENV += $environment;
            putenv($process === false ? $name : $name . '=' . $process);
        }
    }

    public function test_the_committed_mock_configuration_passes(): void
    {
        $configuration = $this->load($this->fixture->mockConfiguration());

        self::assertSame(Environment::Mock, $configuration->environment);
        self::assertSame(Fixture::API_TOKEN, $configuration->engineBlock->apiToken);
        self::assertSame('dezi', $configuration->provider->profile);
        self::assertSame(['id_token', 'envelope', 'statement'], array_keys($configuration->provider->trust->approvedKeyAddresses));
        self::assertSame(['id_token', 'envelope', 'statement'], array_keys($configuration->provider->trust->expectedIssuers));
        $client = $configuration->provider->oidc->clients['ggd'];
        self::assertSame('https://jip.dev.openconext.local/oidc/callback', $client->redirectUri);
        self::assertSame(ClientAuthentication::PrivateKeyJwt, $client->authentication);
        self::assertSame(60, $client->signingKey?->assertionLifetimeSeconds);
        self::assertCount(1, $client->decryptionKeys);
        self::assertSame('dezi_nummer', $configuration->binding->claim);
        self::assertCount(8, $configuration->attributes->claims);
        self::assertSame(['dezi_nummer', 'abonnee_nummer', 'rol_code'], $configuration->services[Fixture::SERVICE]->release);
        self::assertSame(['http://mock-idp'], $configuration->services[Fixture::SERVICE]->allowedOrganisations);

        $profile = $configuration->provider->profileConfiguration;
        self::assertInstanceOf(DeziProfileConfiguration::class, $profile);
        self::assertSame('status_check', $profile->revocation->mode);
        self::assertSame(5, $profile->deliveryRecheckTimeoutSeconds());
    }

    public function test_the_acceptance_template_is_refused_for_its_placeholders_only(): void
    {
        $loader = Fixture::loader(Fixture::projectDir() . '/config/jip/acceptance.yaml.dist', 'acceptance');

        $errors = self::errorsOf(static fn () => $loader->load());

        self::assertCount(19, $errors, implode("\n", $errors));
        foreach ($errors as $error) {
            self::assertMatchesRegularExpression('/(?:is an unreplaced placeholder|has an unreplaced placeholder as its key)\z/', $error);
        }
        self::assertContains('provider.approved_key_addresses.envelope: is an unreplaced placeholder', $errors);
        self::assertContains('provider.envelope.subject_association: is an unreplaced placeholder', $errors);
        self::assertContains('transactions.store.host: is an unreplaced placeholder', $errors);
    }

    public function test_the_filled_acceptance_template_passes(): void
    {
        $template = Yaml::parseFile(Fixture::projectDir() . '/config/jip/acceptance.yaml.dist');
        self::assertIsArray($template);
        self::assertIsArray($template['services']);
        $service = $template['services']['<approved service entity ID>'];
        unset($template['services']['<approved service entity ID>']);
        $template['services']['https://app.ggd.example.nl/saml/metadata'] = $service;
        $changes = [
            [['engineblock', 'return_url_prefix'], 'https://engine.example/authentication/idp/process-sraminterrupt'],
            [['provider', 'clients', 'ggd', 'redirect_uri'], 'https://jip.example/oidc/callback'],
            [['services', 'https://app.ggd.example.nl/saml/metadata', 'allowed_organisations'], ['https://idp.example/metadata']],
            [['provider', 'approved_key_addresses', 'envelope'], 'https://acceptatie.auth.dezi.nl/envelope/jwks'],
            [['provider', 'expected_issuers', 'envelope'], 'acceptance-envelope'],
            [['provider', 'expected_issuers', 'statement'], 'acceptance-statement'],
            [['provider', 'expected_assurance', 'loa_authn'], 'high'],
            [['provider', 'expected_assurance', 'loa_dezi'], 'high'],
            [['provider', 'envelope', 'statement_claim'], 'statement'],
            [['provider', 'envelope', 'subject_association'], 'envelope_sub'],
            [['provider', 'envelope', 'audiences', 'ggd'], 'acceptance-client'],
            [['provider', 'clients', 'ggd', 'client_id'], 'acceptance-client'],
            [['provider', 'clients', 'ggd', 'signing_key', 'certificate'], $this->fixture->directory . '/signing.crt'],
            [['provider', 'clients', 'ggd', 'signing_key', 'private_key'], $this->fixture->directory . '/signing.pem'],
            [['provider', 'clients', 'ggd', 'decryption_keys', 0, 'certificate'], $this->fixture->directory . '/decryption.crt'],
            [['provider', 'clients', 'ggd', 'decryption_keys', 0, 'private_key'], $this->fixture->directory . '/decryption.pem'],
            [['transactions', 'store', 'host'], 'db.jip.example'],
            [['transactions', 'store', 'database'], 'jip_acceptance'],
            [['transactions', 'store', 'user'], 'jip_acceptance'],
            [['transactions', 'store', 'tls_ca'], $this->fixture->directory . '/signing.crt'],
            [['services', 'https://app.ggd.example.nl/saml/metadata', 'connection_policy_version'], 'acceptance-1'],
            [['services', 'https://app.ggd.example.nl/saml/metadata', 'restart_login_url'], 'https://app.ggd.example.nl/login'],
        ];
        // Filling a value must not recreate a required field deleted from the template.
        foreach ($changes as [$keys]) {
            $value = $template;
            foreach ($keys as $key) {
                self::assertIsArray($value);
                self::assertArrayHasKey($key, $value);
                $value = $value[$key];
            }
        }
        $path = $this->fixture->writeConfiguration($this->apply($template, $changes));

        $store = Fixture::loader($path, 'acceptance')->load()->transactions->store;

        self::assertSame('mysql:host=db.jip.example;port=3306;dbname=jip_acceptance;charset=utf8mb4', $store->dsn());
        self::assertSame('jip_acceptance', $store->user);
        self::assertSame('database-password', $store->password);
    }

    public function test_the_acceptance_template_holds_no_mock_assumption(): void
    {
        $template = file_get_contents(Fixture::projectDir() . '/config/jip/acceptance.yaml.dist');
        self::assertIsString($template);

        foreach (['mock-dezi', 'jip-mock-ggd', 'keys/mock/', 'http://eidas.'] as $mockValue) {
            self::assertStringNotContainsString($mockValue, $template);
        }
    }

    /**
     * @param list<array{list<string|int>, mixed}> $changes
     * @param Closure(JipConfiguration): void $assert
     */
    #[DataProvider('validVariants')]
    public function test_valid_variants_pass(array $changes, Closure $assert): void
    {
        $assert($this->load($this->apply($this->fixture->mockConfiguration(), $changes)));
    }

    /**
     * @return iterable<string, array{list<array{list<string|int>, mixed}>, Closure(JipConfiguration): void}>
     */
    public static function validVariants(): iterable
    {
        yield 'an explicit empty organisation list is valid and denies all' => [
            [[[...self::SERVICE_PATH, 'allowed_organisations'], []]],
            static function (JipConfiguration $c): void {
                self::assertSame([], $c->services[Fixture::SERVICE]->allowedOrganisations);
            },
        ];
        yield 'an omitted release takes the claims with default_release' => [
            [[[...self::SERVICE_PATH, 'release'], Fixture::ABSENT]],
            static function (JipConfiguration $c): void {
                self::assertSame(['dezi_nummer', 'abonnee_nummer', 'rol_code'], $c->services[Fixture::SERVICE]->release);
            },
        ];
        yield 'a none client without signing key' => [
            [[[...self::CLIENT_PATH, 'authentication'], 'none'], [self::SIGNING_KEY_PATH, Fixture::ABSENT]],
            static function (JipConfiguration $c): void {
                self::assertNull($c->provider->oidc->clients['ggd']->signingKey);
            },
        ];
        yield 'revocation timeout of exactly half the call timeout' => [
            [[['engineblock', 'call_timeout_seconds'], 8], [['provider', 'revocation', 'timeout_seconds'], 4]],
            static function (JipConfiguration $c): void {
                self::assertSame(8, $c->engineBlock->callTimeoutSeconds);
            },
        ];
        yield 'two decryption keys, newest first, with kid' => [
            [[
                [...self::CLIENT_PATH, 'decryption_keys'],
                static fn (Fixture $f): array => [
                    self::keyEntry($f, 'newer') + ['kid' => 'newer'],
                    self::keyEntry($f, 'decryption'),
                ],
            ]],
            static function (JipConfiguration $c): void {
                $keys = $c->provider->oidc->clients['ggd']->decryptionKeys;
                self::assertCount(2, $keys);
                self::assertSame('newer', $keys[0]->kid);
            },
        ];
        yield 'the same key pair for signing and decryption' => [
            [[
                self::SIGNING_KEY_PATH,
                static fn (Fixture $f): array => self::keyEntry($f, 'decryption') + ['assertion_lifetime_seconds' => 60],
            ]],
            static function (JipConfiguration $c): void {
                self::assertCount(2, $c->clientKeyPairs());
            },
        ];
        yield 'max_age omitted' => [
            [[['provider', 'authorization', 'max_age'], Fixture::ABSENT]],
            static function (JipConfiguration $c): void {
                self::assertNull($c->provider->oidc->authorization->maxAge);
            },
        ];
        yield 'a store on an IPv6 address' => [
            [[['transactions', 'store', 'host'], '2001:db8::1']],
            static function (JipConfiguration $c): void {
                self::assertSame('2001:db8::1', $c->transactions->store->host);
                self::assertStringContainsString('host=2001:db8::1;', $c->transactions->store->dsn());
            },
        ];
        yield 'a store on an IP address and the highest port' => [
            [
                [['transactions', 'store', 'host'], '10.0.0.5'],
                [['transactions', 'store', 'port'], 65535],
                [['transactions', 'store', 'database'], 'jip'],
            ],
            static function (JipConfiguration $c): void {
                self::assertSame('mysql:host=10.0.0.5;port=65535;dbname=jip;charset=utf8mb4', $c->transactions->store->dsn());
            },
        ];
    }

    /**
     * @param list<string|int> $path
     */
    #[DataProvider('invalidVariants')]
    public function test_invalid_variants_are_refused(array $path, mixed $value, string $expectedError): void
    {
        $configuration = $this->apply($this->fixture->mockConfiguration(), [[$path, $value]]);

        $errors = self::errorsOf(fn () => $this->load($configuration));

        self::assertContains($expectedError, $errors, implode("\n", $errors));
    }

    /**
     * @return iterable<string, array{list<string|int>, mixed, string}>
     */
    public static function invalidVariants(): iterable
    {
        yield 'unknown environment' => [['environment'], 'staging', 'environment: must be mock, acceptance or production'];

        // Placeholders and environment references
        yield 'unreplaced placeholder' => [
            ['transactions', 'store'],
            '<shared store with atomic operations>',
            'transactions.store: is an unreplaced placeholder',
        ];
        yield 'a store given as a DSN string' => [
            ['transactions', 'store'],
            'sqlite:var/jip/transactions.sqlite',
            'transactions.store: must be a map',
        ];
        yield 'an unknown store setting' => [
            ['transactions', 'store', 'dsn'],
            'mysql:host=db',
            'transactions.store.dsn: is not a known setting',
        ];
        yield 'a store host with DSN syntax' => [
            ['transactions', 'store', 'host'],
            'db;dbname=other',
            'transactions.store.host: must be a host name or IP address',
        ];
        foreach (['db:3307', 'db.example:3307', '127.0.0.1:3307', '2001:db8:::1'] as $host) {
            yield 'invalid store host ' . $host => [
                ['transactions', 'store', 'host'],
                $host,
                'transactions.store.host: must be a host name or IP address',
            ];
        }
        foreach (['localhost', 'LOCALHOST'] as $host) {
            yield 'socket store host ' . $host => [
                ['transactions', 'store', 'host'],
                $host,
                'transactions.store.host: use 127.0.0.1 for a local TCP connection instead of localhost',
            ];
        }
        yield 'a relative store CA path' => [
            ['transactions', 'store', 'tls_ca'],
            'keys/ca.pem',
            'transactions.store.tls_ca: must be an absolute path to a readable CA certificate file',
        ];
        yield 'a missing store CA file' => [
            ['transactions', 'store', 'tls_ca'],
            '/nonexistent-jip-ca-directory/ca.pem',
            'transactions.store.tls_ca: must be an absolute path to a readable CA certificate file',
        ];
        yield 'a store port above 65535' => [
            ['transactions', 'store', 'port'],
            65536,
            'transactions.store.port: must be a port number up to 65535',
        ];
        yield 'a store port as a string' => [
            ['transactions', 'store', 'port'],
            '3306',
            'transactions.store.port: must be a positive integer',
        ];
        yield 'a store database with DSN syntax' => [
            ['transactions', 'store', 'database'],
            'jip;host=other',
            'transactions.store.database: must be at most 64 letters, digits or underscores',
        ];
        yield 'a store database name over 64 characters' => [
            ['transactions', 'store', 'database'],
            str_repeat('a', 65),
            'transactions.store.database: must be at most 64 letters, digits or underscores',
        ];
        yield 'an empty store user' => [
            ['transactions', 'store', 'user'],
            ' ',
            'transactions.store.user: must be a non-empty string',
        ];
        yield 'a store without a password' => [
            ['transactions', 'store', 'password'],
            Fixture::ABSENT,
            'transactions.store.password: is missing',
        ];
        yield 'placeholder inside a value' => [
            ['provider', 'issuer'],
            'https://<host>/',
            'provider.issuer: is an unreplaced placeholder',
        ];
        yield 'placeholder delivered by an environment variable' => [
            [...self::CLIENT_PATH, 'client_id'],
            static function (): string {
                Fixture::setEnv('JIP_TEST_PLACEHOLDER', '<from DEZI registration>');

                return '%env(JIP_TEST_PLACEHOLDER)%';
            },
            'provider.clients.ggd.client_id: is an unreplaced placeholder',
        ];
        yield 'placeholder as service key' => [
            ['services', '<entity id>'],
            [],
            "services['<entity id>']: has an unreplaced placeholder as its key",
        ];
        yield 'env reference inside a longer value' => [
            ['engineblock', 'api_token'],
            'x%env(EB_API_TOKEN)%',
            'engineblock.api_token: may use %env(NAME)% only as the whole value',
        ];
        yield 'env reference to an unset variable' => [
            ['engineblock', 'api_token'],
            '%env(JIP_TEST_UNSET_VARIABLE)%',
            'engineblock.api_token: refers to environment variable JIP_TEST_UNSET_VARIABLE, which is not set',
        ];

        // Reserved namespace and claim mapping
        yield 'mapped attribute outside the reserved prefix' => [
            ['attributes', 'claims', 'rol_code', 'attribute'],
            'urn:mace:govroam.nl:attribute-def:rol-code',
            'attributes.claims.rol_code.attribute: must lie inside attributes.reserved_prefix',
        ];
        yield 'mapped attribute equal to the prefix' => [
            ['attributes', 'claims', 'rol_code', 'attribute'],
            self::PREFIX,
            'attributes.claims.rol_code.attribute: must lie inside attributes.reserved_prefix',
        ];
        yield 'login flag outside the reserved prefix' => [
            ['attributes', 'login_flag'],
            'urn:mace:govroam.nl:attribute-def:login',
            'attributes.login_flag: must lie inside attributes.reserved_prefix',
        ];
        yield 'a claim mapped onto the login flag' => [
            ['attributes', 'claims', 'rol_naam', 'attribute'],
            self::PREFIX . 'login',
            'attributes.claims.rol_naam.attribute: must differ from attributes.login_flag',
        ];
        yield 'two claims mapped onto one attribute' => [
            ['attributes', 'claims', 'rol_naam', 'attribute'],
            self::PREFIX . 'rol-code',
            'attributes.claims.rol_naam.attribute: is already mapped from another claim',
        ];
        yield 'a claim the profile does not release' => [
            ['attributes', 'claims', 'verklaring_id'],
            ['attribute' => self::PREFIX . 'verklaring-id', 'required' => false, 'default_release' => false],
            'attributes.claims.verklaring_id: is not a claim of profile dezi',
        ];
        yield 'claim without required flag' => [
            ['attributes', 'claims', 'rol_code', 'required'],
            Fixture::ABSENT,
            'attributes.claims.rol_code.required: is missing',
        ];
        yield 'binding attribute inside the reserved prefix' => [
            ['binding', 'organisation_attribute'],
            self::PREFIX . 'organisation-dezi-nummer',
            'binding.organisation_attribute: must lie outside attributes.reserved_prefix',
        ];

        // Binding claim
        yield 'binding claim missing under attributes.claims' => [
            ['binding', 'claim'],
            'dezi-nummer',
            'binding.claim: must name a claim under attributes.claims',
        ];
        yield 'binding claim not marked required' => [
            ['attributes', 'claims', 'dezi_nummer', 'required'],
            false,
            'binding.claim: must name a claim marked required under attributes.claims',
        ];
        yield 'binding claim other than dezi_nummer' => [
            ['binding', 'claim'],
            'abonnee_nummer',
            'binding.claim: is not a binding claim that profile dezi allows',
        ];
        yield 'no setting turns the binding off' => [
            ['binding', 'enabled'],
            false,
            'binding.enabled: is not a known setting',
        ];

        // Services
        yield 'release entry missing under attributes.claims' => [
            [...self::SERVICE_PATH, 'release'],
            ['dezi_nummer', 'loa_dezi'],
            self::SERVICE . '.release[1]: must name a claim under attributes.claims',
        ];
        yield 'service names a missing client' => [
            [...self::SERVICE_PATH, 'client'],
            'other',
            self::SERVICE . '.client: must name a client under provider.clients',
        ];
        yield 'empty connection policy version' => [
            [...self::SERVICE_PATH, 'connection_policy_version'],
            '',
            self::SERVICE . '.connection_policy_version: must be a non-empty string',
        ];
        yield 'missing connection policy version' => [
            [...self::SERVICE_PATH, 'connection_policy_version'],
            Fixture::ABSENT,
            self::SERVICE . '.connection_policy_version: is missing',
        ];
        yield 'numeric connection policy version' => [
            [...self::SERVICE_PATH, 'connection_policy_version'],
            3,
            self::SERVICE . '.connection_policy_version: must be a non-empty string',
        ];
        yield 'missing organisation list' => [
            [...self::SERVICE_PATH, 'allowed_organisations'],
            Fixture::ABSENT,
            self::SERVICE . '.allowed_organisations: is missing',
        ];
        yield 'organisation list that is a string' => [
            [...self::SERVICE_PATH, 'allowed_organisations'],
            'http://mock-idp',
            self::SERVICE . '.allowed_organisations: must be a list',
        ];
        yield 'organisation list that is a map' => [
            [...self::SERVICE_PATH, 'allowed_organisations'],
            ['idp' => 'http://mock-idp'],
            self::SERVICE . '.allowed_organisations: must be a list',
        ];
        yield 'duplicate organisation' => [
            [...self::SERVICE_PATH, 'allowed_organisations'],
            ['http://mock-idp', 'http://mock-idp'],
            self::SERVICE . '.allowed_organisations[1]: is a duplicate entry',
        ];
        yield 'blank organisation entry' => [
            [...self::SERVICE_PATH, 'allowed_organisations'],
            ['http://mock-idp', ' '],
            self::SERVICE . '.allowed_organisations[1]: must be a non-empty string',
        ];
        yield 'restart login URL not https' => [
            [...self::SERVICE_PATH, 'restart_login_url'],
            'http://jip-test-sp.dev.openconext.local/',
            self::SERVICE . '.restart_login_url: must be an absolute https URL',
        ];
        yield 'relative restart login URL' => [
            [...self::SERVICE_PATH, 'restart_login_url'],
            '/login',
            self::SERVICE . '.restart_login_url: must be an absolute https URL',
        ];
        yield 'unknown service setting' => [
            [...self::SERVICE_PATH, 'alowed_organisations'],
            [],
            self::SERVICE . '.alowed_organisations: is not a known setting',
        ];

        // Key addresses, issuers and assurance per message type
        yield 'approved key addresses not a map' => [
            ['provider', 'approved_key_addresses'],
            'https://mock-dezi.dev.openconext.local/jwks.json',
            'provider.approved_key_addresses: must be a map',
        ];
        yield 'approved key address missing for the envelope' => [
            ['provider', 'approved_key_addresses', 'envelope'],
            Fixture::ABSENT,
            'provider.approved_key_addresses.envelope: is missing',
        ];
        yield 'approved key address as a list' => [
            ['provider', 'approved_key_addresses', 'statement'],
            ['https://mock-dezi.dev.openconext.local/dezi/jwks.json'],
            'provider.approved_key_addresses.statement: must be a non-empty string',
        ];
        yield 'approved key address not https' => [
            ['provider', 'approved_key_addresses', 'id_token'],
            'http://mock-dezi.dev.openconext.local/jwks.json',
            'provider.approved_key_addresses.id_token: must be an absolute https URL',
        ];
        yield 'revocation list key address without the list mode' => [
            ['provider', 'approved_key_addresses', 'revocation_list'],
            'https://mock-dezi.dev.openconext.local/dezi/jwks.json',
            'provider.approved_key_addresses.revocation_list: is not a message type the configured profile uses',
        ];
        yield 'expected issuers not a map' => [
            ['provider', 'expected_issuers'],
            ['https://mock-dezi.dev.openconext.local'],
            'provider.expected_issuers: must be a map',
        ];
        yield 'expected issuer missing for the statement' => [
            ['provider', 'expected_issuers', 'statement'],
            Fixture::ABSENT,
            'provider.expected_issuers.statement: is missing',
        ];
        yield 'empty expected issuer for the ID token' => [
            ['provider', 'expected_issuers', 'id_token'],
            '',
            'provider.expected_issuers.id_token: must be a non-empty string',
        ];
        yield 'expected assurance missing for loa_dezi' => [
            ['provider', 'expected_assurance', 'loa_dezi'],
            Fixture::ABSENT,
            'provider.expected_assurance.loa_dezi: is missing',
        ];

        // Clients and keys
        yield 'missing client redirect URI' => [
            [...self::CLIENT_PATH, 'redirect_uri'],
            Fixture::ABSENT,
            'provider.clients.ggd.redirect_uri: is missing',
        ];
        yield 'non-HTTPS client redirect URI' => [
            [...self::CLIENT_PATH, 'redirect_uri'],
            'http://jip.dev.openconext.local/oidc/callback',
            'provider.clients.ggd.redirect_uri: must be an absolute https URL',
        ];
        yield 'client redirect URI with another path' => [
            [...self::CLIENT_PATH, 'redirect_uri'],
            'https://jip.dev.openconext.local/another-callback',
            'provider.clients.ggd.redirect_uri: must have the path /oidc/callback and no query or fragment',
        ];
        yield 'client redirect URI with a query' => [
            [...self::CLIENT_PATH, 'redirect_uri'],
            'https://jip.dev.openconext.local/oidc/callback?login=1',
            'provider.clients.ggd.redirect_uri: must have the path /oidc/callback and no query or fragment',
        ];
        yield 'client redirect URI with a fragment' => [
            [...self::CLIENT_PATH, 'redirect_uri'],
            'https://jip.dev.openconext.local/oidc/callback#login',
            'provider.clients.ggd.redirect_uri: must have the path /oidc/callback and no query or fragment',
        ];
        yield 'client without decryption key' => [
            [...self::CLIENT_PATH, 'decryption_keys'],
            [],
            'provider.clients.ggd.decryption_keys: must hold at least one decryption key',
        ];
        yield 'decryption private key that does not match its certificate' => [
            [...self::DECRYPTION_KEY_PATH, 'private_key'],
            static fn (Fixture $f): string => $f->writeKeyPair('other') . '.pem',
            'provider.clients.ggd.decryption_keys[0].private_key: does not match its certificate',
        ];
        yield 'unreadable decryption private key' => [
            [...self::DECRYPTION_KEY_PATH, 'private_key'],
            static fn (Fixture $f): string => $f->directory . '/absent.pem',
            'provider.clients.ggd.decryption_keys[0].private_key: names a file that cannot be read',
        ];
        yield 'decryption private key that is a certificate' => [
            [...self::DECRYPTION_KEY_PATH, 'private_key'],
            static fn (Fixture $f): string => $f->directory . '/decryption.crt',
            'provider.clients.ggd.decryption_keys[0].private_key: cannot be read as an unencrypted PEM private key',
        ];
        yield 'certificate that is a private key' => [
            [...self::DECRYPTION_KEY_PATH, 'certificate'],
            static fn (Fixture $f): string => $f->directory . '/decryption.pem',
            'provider.clients.ggd.decryption_keys[0].certificate: is not a PEM X.509 certificate',
        ];
        yield 'EC key' => [
            self::DECRYPTION_KEY_PATH,
            static fn (Fixture $f): array => self::keyEntry($f, 'ec', type: 'ec'),
            'provider.clients.ggd.decryption_keys[0].private_key: must be an RSA key of at least 2048 bits',
        ];
        yield 'RSA key below 2048 bits' => [
            self::SIGNING_KEY_PATH,
            static fn (Fixture $f): array => self::keyEntry($f, 'weak', bits: 1024) + ['assertion_lifetime_seconds' => 60],
            'provider.clients.ggd.signing_key.private_key: must be an RSA key of at least 2048 bits',
        ];
        yield 'unknown client authentication' => [
            [...self::CLIENT_PATH, 'authentication'],
            'client_secret_basic',
            'provider.clients.ggd.authentication: must be private_key_jwt or none',
        ];
        yield 'private_key_jwt client without signing key' => [
            self::SIGNING_KEY_PATH,
            Fixture::ABSENT,
            'provider.clients.ggd.signing_key: is required with private_key_jwt',
        ];
        yield 'unreadable signing private key' => [
            [...self::SIGNING_KEY_PATH, 'private_key'],
            static fn (Fixture $f): string => $f->directory . '/absent.pem',
            'provider.clients.ggd.signing_key.private_key: names a file that cannot be read',
        ];
        yield 'signing private key that does not match its certificate' => [
            [...self::SIGNING_KEY_PATH, 'private_key'],
            static fn (Fixture $f): string => $f->writeKeyPair('other') . '.pem',
            'provider.clients.ggd.signing_key.private_key: does not match its certificate',
        ];
        yield 'none client with signing key' => [
            [...self::CLIENT_PATH, 'authentication'],
            'none',
            'provider.clients.ggd.signing_key: must be absent with authentication none',
        ];
        yield 'no clients' => [['provider', 'clients'], [], 'provider.clients: must hold at least one client'];
        yield 'scope without openid' => [
            ['provider', 'authorization', 'scope'],
            'profile',
            'provider.authorization.scope: must include openid',
        ];
        yield 'negative max_age' => [
            ['provider', 'authorization', 'max_age'],
            -1,
            'provider.authorization.max_age: must be a non-negative integer',
        ];

        // EngineBlock
        yield 'API token of 31 characters' => [
            ['engineblock', 'api_token'],
            str_repeat('a', 31),
            'engineblock.api_token: must be at least 32 characters',
        ];
        yield 'empty API token' => [
            ['engineblock', 'api_token'],
            '',
            'engineblock.api_token: must be a non-empty string',
        ];
        yield 'return URL prefix not https' => [
            ['engineblock', 'return_url_prefix'],
            'http://engine.dev.openconext.local/authentication/idp/process-sraminterrupt',
            'engineblock.return_url_prefix: must be an absolute https URL',
        ];

        // Provider
        yield 'unknown profile' => [['provider', 'profile'], 'other', 'provider.profile: must be one of: dezi'];
        yield 'issuer not https' => [
            ['provider', 'issuer'],
            'http://mock-dezi.dev.openconext.local',
            'provider.issuer: must be an absolute https URL',
        ];
        yield 'issuer with credentials' => [
            ['provider', 'issuer'],
            'https://user:pass@mock-dezi.dev.openconext.local',
            'provider.issuer: must be an absolute https URL',
        ];

        // Revocation
        yield 'status address not https' => [
            ['provider', 'revocation', 'status_address'],
            'http://mock-dezi.dev.openconext.local/status/v1/verklaring/{verklaring_id}',
            'provider.revocation.status_address: must be an absolute https URL',
        ];
        yield 'status address without {verklaring_id}' => [
            ['provider', 'revocation', 'status_address'],
            'https://mock-dezi.dev.openconext.local/status/v1/verklaring/',
            'provider.revocation.status_address: must contain {verklaring_id} exactly once',
        ];
        yield 'status address with {verklaring_id} twice' => [
            ['provider', 'revocation', 'status_address'],
            'https://mock-dezi.dev.openconext.local/{verklaring_id}/status/v1/verklaring/{verklaring_id}',
            'provider.revocation.status_address: must contain {verklaring_id} exactly once',
        ];
        yield 'revocation list mode' => [
            ['provider', 'revocation', 'mode'],
            'status_check_with_list',
            'provider.revocation.mode: status_check_with_list is not supported; this version uses status_check only',
        ];
        yield 'unknown revocation mode' => [
            ['provider', 'revocation', 'mode'],
            'none',
            'provider.revocation.mode: must be status_check',
        ];
        yield 'revocation list address' => [
            ['provider', 'revocation', 'list_address'],
            'https://mock-dezi.dev.openconext.local/revocatiecontrole/v1',
            'provider.revocation.list_address: is only used with status_check_with_list, which is not supported',
        ];
        yield 'revocation timeout more than half of the call timeout' => [
            ['provider', 'revocation', 'timeout_seconds'],
            6,
            'provider.revocation.timeout_seconds: must not be more than half of engineblock.call_timeout_seconds',
        ];

        // Positive integers
        $positiveIntegers = [
            ['engineblock', 'call_timeout_seconds'],
            ['provider', 'clock_skew_seconds'],
            ['provider', 'key_cache_seconds'],
            ['provider', 'key_refetch_min_interval_seconds'],
            ['provider', 'certificate_expiry_warning_days'],
            [...self::SIGNING_KEY_PATH, 'assertion_lifetime_seconds'],
            ['provider', 'revocation', 'timeout_seconds'],
            ['provider', 'revocation', 'decision_validity_seconds'],
            ['transactions', 'lifetime_seconds'],
        ];
        $notPositive = ['zero' => 0, 'negative' => -5, 'string' => '10', 'float' => 1.5, 'missing' => Fixture::ABSENT];
        foreach ($positiveIntegers as $path) {
            $name = implode('.', $path);
            foreach ($notPositive as $label => $value) {
                yield sprintf('%s %s', $name, $label) => [
                    $path,
                    $value,
                    $name . ($value === Fixture::ABSENT ? ': is missing' : ': must be a positive integer'),
                ];
            }
        }

        yield 'unknown top-level setting' => [['provder'], [], 'provder: is not a known setting'];
    }

    /**
     * @return iterable<string, array{Environment}>
     */
    public static function deployedEnvironments(): iterable
    {
        yield 'acceptance' => [Environment::Acceptance];
        yield 'production' => [Environment::Production];
    }

    #[DataProvider('deployedEnvironments')]
    public function test_a_deployed_store_requires_a_ca_file(Environment $environment): void
    {
        $configuration = Fixture::with($this->fixture->mockConfiguration(), ['environment'], $environment->value);
        $file = $this->fixture->writeConfiguration($configuration);

        $errors = self::errorsOf(static fn () => Fixture::loader($file, $environment->value)->load());

        self::assertSame(['transactions.store.tls_ca: is missing'], $errors);
    }

    #[DataProvider('deployedEnvironments')]
    public function test_the_shared_store_is_accepted_outside_mock(Environment $environment): void
    {
        $configuration = Fixture::with($this->fixture->mockConfiguration(), ['environment'], $environment->value);
        $configuration = Fixture::with($configuration, ['transactions', 'store', 'tls_ca'], $this->fixture->directory . '/signing.crt');
        $file = $this->fixture->writeConfiguration($configuration);

        self::assertSame($environment, Fixture::loader($file, $environment->value)->load()->environment);
    }

    public function test_environment_must_equal_connector_environment(): void
    {
        $file = $this->fixture->writeConfiguration($this->fixture->mockConfiguration());

        $errors = self::errorsOf(static fn () => Fixture::loader($file, 'acceptance')->load());

        self::assertContains('environment: differs from CONNECTOR_ENVIRONMENT', $errors);
    }

    public function test_connector_environment_must_be_set(): void
    {
        $file = $this->fixture->writeConfiguration($this->fixture->mockConfiguration());

        foreach ([null, ''] as $deploymentEnvironment) {
            $errors = self::errorsOf(static fn () => Fixture::loader($file, $deploymentEnvironment)->load());

            self::assertContains('CONNECTOR_ENVIRONMENT: is not set by the deployment', $errors);
        }
    }

    public function test_config_file_must_be_set_and_readable(): void
    {
        self::assertContains(
            'JIP_CONFIG_FILE: is not set by the deployment',
            self::errorsOf(static fn () => Fixture::loader(null)->load()),
        );
        self::assertContains(
            'JIP_CONFIG_FILE: names a file that cannot be read',
            self::errorsOf(fn () => Fixture::loader($this->fixture->directory . '/absent.yaml')->load()),
        );
    }

    public function test_invalid_yaml_is_reported_without_its_content(): void
    {
        $file = $this->fixture->directory . '/broken.yaml';
        file_put_contents($file, "engineblock:\n  api_token: 'secret-value-in-file\n");

        $errors = self::errorsOf(static fn () => Fixture::loader($file)->load());

        self::assertCount(1, $errors);
        self::assertStringStartsWith('JIP_CONFIG_FILE: is not valid YAML', $errors[0]);
        self::assertStringNotContainsString('secret-value-in-file', $errors[0]);
    }

    public function test_errors_never_contain_configured_values(): void
    {
        $configuration = $this->apply($this->fixture->mockConfiguration(), [
            [['engineblock', 'api_token'], 'too-short-secret'],
            [['provider', 'issuer'], 'http://issuer-value.example'],
        ]);

        $errors = implode("\n", self::errorsOf(fn () => $this->load($configuration)));

        self::assertStringContainsString('engineblock.api_token', $errors);
        self::assertStringNotContainsString('too-short-secret', $errors);
        self::assertStringNotContainsString('issuer-value', $errors);
    }

    public function test_all_problems_are_reported_at_once(): void
    {
        $configuration = $this->apply($this->fixture->mockConfiguration(), [
            [['engineblock', 'api_token'], 'short'],
            [['binding', 'claim'], 'abonnee_nummer'],
            [['provider', 'revocation', 'status_address'], 'https://mock-dezi.dev.openconext.local/'],
        ]);

        self::assertEqualsCanonicalizing([
            'engineblock.api_token: must be at least 32 characters',
            'binding.claim: is not a binding claim that profile dezi allows',
            'provider.revocation.status_address: must contain {verklaring_id} exactly once',
        ], self::errorsOf(fn () => $this->load($configuration)));
    }

    /**
     * @return array{certificate: string, private_key: string}
     */
    private static function keyEntry(Fixture $fixture, string $name, string $type = 'rsa', int $bits = 2048): array
    {
        $base = $fixture->writeKeyPair($name, type: $type, bits: $bits);

        return ['certificate' => $base . '.crt', 'private_key' => $base . '.pem'];
    }

    /**
     * @param array<mixed> $configuration
     * @param list<array{list<string|int>, mixed}> $changes values may be Closure(Fixture): mixed
     * @return array<mixed>
     */
    private function apply(array $configuration, array $changes): array
    {
        foreach ($changes as [$path, $value]) {
            $configuration = Fixture::with(
                $configuration,
                $path,
                $value instanceof Closure ? $value($this->fixture) : $value,
            );
        }

        return $configuration;
    }

    /**
     * @param array<mixed> $configuration
     */
    private function load(array $configuration): JipConfiguration
    {
        return Fixture::loader($this->fixture->writeConfiguration($configuration))->load();
    }

    /**
     * @param Closure(): mixed $load
     * @return list<string>
     */
    private static function errorsOf(Closure $load): array
    {
        try {
            $load();
        } catch (InvalidConfiguration $exception) {
            return $exception->errors;
        }

        self::fail('The configuration was accepted.');
    }
}
