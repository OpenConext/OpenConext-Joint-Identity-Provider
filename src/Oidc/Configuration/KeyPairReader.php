<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Configuration;

use DateTimeImmutable;
use JointIdentityProvider\Core\Configuration\Reader\ConfigNode;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Reads `certificate` and `private_key` of a key entry and checks that both can be read, that the key is
 * RSA (RS256 and RSA-OAEP, design §14) and that it matches the certificate. Relative paths resolve
 * against the project directory.
 */
final readonly class KeyPairReader
{
    private const int MINIMUM_RSA_BITS = 2048;

    public function __construct(#[Autowire('%kernel.project_dir%')] private string $projectDir)
    {
    }

    /**
     * @param list<string> $extraKeys further keys the entry may hold
     */
    public function read(ConfigNode $entry, array $extraKeys = []): ?KeyPair
    {
        if (!$entry->requireMap()) {
            return null;
        }
        $entry->allowOnly('certificate', 'private_key', 'kid', ...$extraKeys);

        $kid = $entry->get('kid')->optionalString();
        $certificatePem = $this->readFile($entry->get('certificate'));
        $privateKeyPem = $this->readFile($entry->get('private_key'));

        $certificate = null;
        if ($certificatePem !== null) {
            $certificate = @openssl_x509_read($certificatePem);
            if (!$certificate instanceof OpenSSLCertificate) {
                $entry->get('certificate')->error('is not a PEM X.509 certificate');
                $certificate = null;
            }
        }

        $privateKey = null;
        if ($privateKeyPem !== null) {
            $privateKey = @openssl_pkey_get_private($privateKeyPem);
            if (!$privateKey instanceof OpenSSLAsymmetricKey) {
                $entry->get('private_key')->error('cannot be read as an unencrypted PEM private key');
                $privateKey = null;
            } elseif (!self::isStrongRsaKey($privateKey)) {
                $entry->get('private_key')->error(
                    sprintf('must be an RSA key of at least %d bits', self::MINIMUM_RSA_BITS),
                );
                $privateKey = null;
            }
        }

        self::clearOpenSslErrors();

        if ($certificate === null || $privateKey === null) {
            return null;
        }

        if (!openssl_x509_check_private_key($certificate, $privateKey)) {
            self::clearOpenSslErrors();
            $entry->get('private_key')->error('does not match its certificate');

            return null;
        }

        $validTo = openssl_x509_parse($certificate)['validTo_time_t'] ?? null;
        if (!is_int($validTo)) {
            $entry->get('certificate')->error('has no readable expiry date');

            return null;
        }

        return new KeyPair(
            $entry->path,
            $certificatePem,
            $privateKeyPem,
            new DateTimeImmutable('@' . $validTo),
            $kid,
        );
    }

    private function readFile(ConfigNode $node): ?string
    {
        $path = $node->requireString();
        if ($path === null) {
            return null;
        }

        $absolute = str_starts_with($path, '/') ? $path : $this->projectDir . '/' . $path;
        if (!is_file($absolute) || !is_readable($absolute)) {
            $node->error('names a file that cannot be read');

            return null;
        }

        $contents = @file_get_contents($absolute);
        if ($contents === false || $contents === '') {
            $node->error('names a file that cannot be read');

            return null;
        }

        return $contents;
    }

    private static function isStrongRsaKey(OpenSSLAsymmetricKey $key): bool
    {
        $details = openssl_pkey_get_details($key);

        return is_array($details)
            && ($details['type'] ?? null) === OPENSSL_KEYTYPE_RSA
            && ($details['bits'] ?? 0) >= self::MINIMUM_RSA_BITS;
    }

    private static function clearOpenSslErrors(): void
    {
        while (openssl_error_string() !== false) {
            // OpenSSL keeps an error queue per process; drain it so later checks start clean.
        }
    }
}
