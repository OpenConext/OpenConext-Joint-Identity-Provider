<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Support;

use JointIdentityProvider\Core\Configuration\ConfigurationLoader;
use JointIdentityProvider\Core\Configuration\ConfigurationParser;
use JointIdentityProvider\Core\Profile\ProfileRegistry;
use JointIdentityProvider\Oidc\Cache\ProviderCache;
use JointIdentityProvider\Oidc\Configuration\KeyPairReader;
use JointIdentityProvider\Oidc\Configuration\OidcConfigurationParser;
use JointIdentityProvider\Oidc\Http\ProviderHttpClient;
use JointIdentityProvider\Oidc\Jose\SignedMessageVerifier;
use JointIdentityProvider\Oidc\Keys\KeyResolver;
use JointIdentityProvider\Profile\Dezi\DeziProfile;
use JointIdentityProvider\Profile\Dezi\ProofValidator;
use JointIdentityProvider\Profile\Dezi\RevocationChecker;
use JointIdentityProvider\Profile\Dezi\UserInfoReader;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;
use RuntimeException;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\Store\InMemoryStore;
use Symfony\Component\Yaml\Yaml;

/**
 * Builds configurations from the committed config/jip/mock.yaml with freshly generated test keys.
 */
final class ConfigurationFixture
{
    public const string API_TOKEN = 'test-token-0123456789abcdef0123456789abcdef';
    public const string SERVICE = 'https://jip-test-sp.dev.openconext.local/saml/metadata';
    public const string ABSENT = "\0absent";

    public readonly string $directory;

    /** @var array<string, array{string, string}> generated certificate and key PEMs, reused across tests */
    private static array $generated = [];

    /** @var array<string, array{array<string, mixed>, array<string, mixed>, string|false}> */
    private static array $previousEnvironment = [];

    public function __construct()
    {
        $this->directory = sys_get_temp_dir() . '/jip-tests-' . bin2hex(random_bytes(6));
        (new Filesystem())->mkdir($this->directory, 0700);
        $this->writeKeyPair('signing');
        $this->writeKeyPair('decryption');
    }

    public static function projectDir(): string
    {
        return dirname(__DIR__, 2);
    }

    public function remove(): void
    {
        foreach (array_keys(self::$previousEnvironment) as $name) {
            self::setEnv($name, null);
        }
        (new Filesystem())->remove($this->directory);
    }

    /**
     * The committed mock configuration with its key paths pointing at this fixture's keys.
     *
     * @return array<string, mixed>
     */
    public function mockConfiguration(): array
    {
        $configuration = Yaml::parseFile(self::projectDir() . '/config/jip/mock.yaml');
        if (!is_array($configuration)) {
            throw new RuntimeException('config/jip/mock.yaml is not a map.');
        }

        /** @var array<string, mixed> $configuration */
        $configuration = self::replacePaths($configuration, [
            'keys/mock/ggd-signing.crt' => $this->directory . '/signing.crt',
            'keys/mock/ggd-signing.pem' => $this->directory . '/signing.pem',
            'keys/mock/ggd-decryption.crt' => $this->directory . '/decryption.crt',
            'keys/mock/ggd-decryption.pem' => $this->directory . '/decryption.pem',
        ]);

        /** @var array<string, mixed> $configuration */
        $configuration = self::with($configuration, ['transactions', 'store'], TestDatabase::storeSettings());

        return $configuration;
    }

    /**
     * @param array<array-key, mixed> $configuration
     */
    public function writeConfiguration(array $configuration, string $name = 'jip.yaml'): string
    {
        $path = $this->directory . '/' . $name;
        file_put_contents($path, Yaml::dump($configuration, 10, 2));

        return $path;
    }

    public static function loader(?string $configFile, ?string $deploymentEnvironment = 'mock'): ConfigurationLoader
    {
        $parser = new ConfigurationParser(
            new ProfileRegistry([self::deziProfile()]),
            new OidcConfigurationParser(new KeyPairReader(self::projectDir())),
        );

        return new ConfigurationLoader($parser, self::projectDir(), $configFile, $deploymentEnvironment);
    }

    /**
     * A DEZI profile for configuration parsing; its outgoing requests reach no provider.
     */
    public static function deziProfile(): DeziProfile
    {
        $http = new ProviderHttpClient(new MockHttpClient(static fn (): MockResponse => new MockResponse('', ['http_code' => 404])));
        $clock = new NativeClock();
        $cache = new ProviderCache(new ArrayAdapter(), new LockFactory(new InMemoryStore()));
        $keys = new KeyResolver($http, $cache, $clock);

        return new DeziProfile(
            new UserInfoReader($http),
            new ProofValidator(new SignedMessageVerifier($keys)),
            new RevocationChecker($http, $clock),
            $clock,
        );
    }

    public static function setEnv(string $name, ?string $value): void
    {
        if ($value === null) {
            if (isset(self::$previousEnvironment[$name])) {
                [$server, $environment, $process] = self::$previousEnvironment[$name];
                unset($_SERVER[$name], $_ENV[$name], self::$previousEnvironment[$name]);
                $_SERVER += $server;
                $_ENV += $environment;
                putenv($process === false ? $name : $name . '=' . $process);
            }

            return;
        }

        self::$previousEnvironment[$name] ??= [
            array_intersect_key($_SERVER, [$name => true]),
            array_intersect_key($_ENV, [$name => true]),
            getenv($name),
        ];
        $_SERVER[$name] = $value;
        $_ENV[$name] = $value;
    }

    /**
     * Writes <name>.pem and <name>.crt; returns the base path without extension.
     */
    public function writeKeyPair(string $name, int $days = 365, string $type = 'rsa', int $bits = 2048): string
    {
        $cacheKey = implode('/', [$name, $days, $type, $bits]);
        self::$generated[$cacheKey] ??= self::generateKeyPair($name, $days, $type, $bits);
        [$certificatePem, $keyPem] = self::$generated[$cacheKey];

        $base = $this->directory . '/' . $name;
        file_put_contents($base . '.crt', $certificatePem);
        file_put_contents($base . '.pem', $keyPem);
        chmod($base . '.pem', 0600);

        return $base;
    }

    /**
     * @return array{string, string}
     */
    private static function generateKeyPair(string $name, int $days, string $type, int $bits): array
    {
        $options = $type === 'ec'
            ? ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']
            : ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $bits];

        $key = openssl_pkey_new($options);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new RuntimeException('Cannot generate a test key.');
        }

        // openssl_csr_new() takes the key by reference; keep $key's type for the calls below.
        $csrKey = $key;
        $csr = openssl_csr_new(['commonName' => 'JIP test ' . $name], $csrKey, ['digest_alg' => 'sha256']);
        if (!$csr instanceof OpenSSLCertificateSigningRequest) {
            throw new RuntimeException('Cannot create a test certificate request.');
        }

        $certificate = openssl_csr_sign($csr, null, $key, $days, ['digest_alg' => 'sha256']);
        if (
            !$certificate instanceof OpenSSLCertificate
            || !openssl_x509_export($certificate, $certificatePem)
            || !openssl_pkey_export($key, $keyPem)
            || !is_string($certificatePem)
            || !is_string($keyPem)
        ) {
            throw new RuntimeException('Cannot export the test key pair.');
        }

        return [$certificatePem, $keyPem];
    }

    /**
     * A copy of $array with the value at $path set; ABSENT removes it.
     *
     * @param array<mixed> $array
     * @param list<string|int> $path
     * @return array<mixed>
     */
    public static function with(array $array, array $path, mixed $value): array
    {
        $key = array_shift($path);
        if ($key === null) {
            return $array;
        }

        if ($path === []) {
            if ($value === self::ABSENT) {
                unset($array[$key]);
            } else {
                $array[$key] = $value;
            }

            return $array;
        }

        $child = $array[$key] ?? [];
        $array[$key] = self::with(is_array($child) ? $child : [], $path, $value);

        return $array;
    }

    /**
     * @param array<mixed> $array
     * @param list<string|int> $path
     */
    public static function at(array $array, array $path): mixed
    {
        $value = $array;
        foreach ($path as $key) {
            if (!is_array($value) || !array_key_exists($key, $value)) {
                return null;
            }
            $value = $value[$key];
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $value
     * @param array<string, string> $replacements
     * @return array<array-key, mixed>
     */
    private static function replacePaths(array $value, array $replacements): array
    {
        foreach ($value as $key => $child) {
            if (is_array($child)) {
                $value[$key] = self::replacePaths($child, $replacements);
            } elseif (is_string($child) && isset($replacements[$child])) {
                $value[$key] = $replacements[$child];
            }
        }

        return $value;
    }
}
