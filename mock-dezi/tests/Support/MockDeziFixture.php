<?php

declare(strict_types=1);

namespace MockDezi\Tests\Support;

use RuntimeException;
use Symfony\Component\Yaml\Yaml;

/**
 * A throw-away environment for one test: the mock's signing keys, a client with a signing and a decryption key
 * pair (the private halves stay with the test, which plays JIP), a configuration file and a state file.
 */
final class MockDeziFixture
{
    public const string CLIENT_ID = 'jip-mock-ggd';
    public const string NONE_CLIENT_ID = 'jip-mock-ggd-none';
    public const string REDIRECT_URI = 'https://jip.dev.openconext.local/oidc/callback';

    public readonly string $directory;
    public readonly string $signingKey;
    public readonly string $signingCertificate;
    public readonly string $otherSigningKey;
    public readonly string $otherSigningCertificate;
    public readonly string $decryptionKeyPem;

    /** @var array<string, array{string, string}> */
    private static array $keyCache = [];

    /**
     * @param array<string, mixed> $overrides top-level settings replaced in config/mock-dezi.yaml
     */
    public function __construct(array $overrides = [], bool $registerOtherSigningKey = false)
    {
        $this->directory = sys_get_temp_dir() . '/mock-dezi-test-' . bin2hex(random_bytes(6));
        mkdir($this->directory . '/keys', 0o700, true);
        mkdir($this->directory . '/client', 0o700, true);

        foreach (['id-token', 'envelope', 'statement', 'rogue'] as $name) {
            file_put_contents($this->directory . '/keys/' . $name . '.pem', self::cachedKey($name)[0]);
        }
        [$this->signingKey, $this->signingCertificate] = self::cachedKey('client-signing');
        [$this->otherSigningKey, $this->otherSigningCertificate] = self::cachedKey('client-signing-other');
        [$this->decryptionKeyPem, $decryptionCertificate] = self::cachedKey('client-decryption');
        file_put_contents($this->directory . '/client/signing.crt', $this->signingCertificate);
        file_put_contents($this->directory . '/client/signing-other.crt', $this->otherSigningCertificate);
        file_put_contents($this->directory . '/client/decryption.crt', $decryptionCertificate);

        $configuration = Yaml::parseFile(dirname(__DIR__, 2) . '/config/mock-dezi.yaml');
        if (!is_array($configuration)) {
            throw new RuntimeException('config/mock-dezi.yaml is not a map');
        }
        $configuration['timeout_delay_seconds'] = 1;
        $configuration['clients'] = [
            self::CLIENT_ID => [
                'redirect_uris' => [self::REDIRECT_URI],
                'authentication' => 'private_key_jwt',
                'signing_certificates' => $registerOtherSigningKey
                    ? ['signing.crt', 'signing-other.crt']
                    : ['signing.crt'],
                'encryption_certificate' => 'decryption.crt',
                'encryption_kid' => 'test-decryption-kid',
                'envelope_audience' => 'test-envelope-audience',
                'sector_identifier' => 'jip.dev.openconext.local',
            ],
            self::NONE_CLIENT_ID => [
                'redirect_uris' => [self::REDIRECT_URI],
                'authentication' => 'none',
                'signing_certificates' => [],
                'encryption_certificate' => 'decryption.crt',
                'encryption_kid' => null,
                'envelope_audience' => self::NONE_CLIENT_ID,
                'sector_identifier' => 'jip.dev.openconext.local',
            ],
        ];
        file_put_contents($this->directory . '/mock-dezi.yaml', Yaml::dump($overrides + $configuration, 6));
    }

    public function apply(): void
    {
        self::setEnv('MOCK_DEZI_CONFIG_FILE', $this->directory . '/mock-dezi.yaml');
        self::setEnv('MOCK_DEZI_CLIENT_KEYS_DIR', $this->directory . '/client');
        self::setEnv('MOCK_DEZI_KEYS_DIR', $this->directory . '/keys');
        self::setEnv('MOCK_DEZI_STATE_FILE', $this->directory . '/state.json');
    }

    public function remove(): void
    {
        foreach (['MOCK_DEZI_CONFIG_FILE', 'MOCK_DEZI_CLIENT_KEYS_DIR', 'MOCK_DEZI_KEYS_DIR', 'MOCK_DEZI_STATE_FILE'] as $name) {
            self::setEnv($name, null);
        }
        exec('rm -rf ' . escapeshellarg($this->directory));
    }

    public static function setEnv(string $name, ?string $value): void
    {
        if ($value === null) {
            unset($_SERVER[$name], $_ENV[$name]);
            putenv($name);

            return;
        }
        $_SERVER[$name] = $_ENV[$name] = $value;
        putenv($name . '=' . $value);
    }

    /**
     * RSA 2048 keys, generated once per test run: [private key PEM, self-signed certificate PEM].
     *
     * @return array{string, string}
     */
    private static function cachedKey(string $name): array
    {
        if (!isset(self::$keyCache[$name])) {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            if ($key === false) {
                throw new RuntimeException('Cannot create a test key');
            }
            $csrKey = $key;
            $csr = openssl_csr_new(['commonName' => 'mock-dezi test ' . $name], $csrKey, ['digest_alg' => 'sha256']);
            if ($csr === false || $csr === true) {
                throw new RuntimeException('Cannot create a test CSR');
            }
            $certificate = openssl_csr_sign($csr, null, $key, 30, ['digest_alg' => 'sha256']);
            if ($certificate === false) {
                throw new RuntimeException('Cannot sign a test certificate');
            }
            openssl_x509_export($certificate, $certificatePem);
            openssl_pkey_export($key, $keyPem);
            if (!is_string($certificatePem) || !is_string($keyPem)) {
                throw new RuntimeException('Cannot export a test key');
            }
            self::$keyCache[$name] = [$keyPem, $certificatePem];
        }

        return self::$keyCache[$name];
    }
}
