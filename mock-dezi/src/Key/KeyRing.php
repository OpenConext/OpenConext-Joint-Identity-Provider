<?php

declare(strict_types=1);

namespace MockDezi\Key;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use MockDezi\Configuration\Paths;
use MockDezi\Message\Jose;
use RuntimeException;
use Throwable;

/**
 * The mock's signing keys (bin/init-keys): one per message type, and one "rogue" key that is never published.
 */
final class KeyRing
{
    public const string ROGUE_FILE = 'rogue.pem';
    public const string UNKNOWN_KID = 'mock-dezi-unpublished-key';

    /** @var array<string, array{string, JWK}> file => private key PEM and public JWK with kid */
    private array $keys = [];

    public function __construct(
        private readonly string $projectDir,
        private readonly string $keysDirectory,
    ) {
    }

    public function privateKey(MessageType $type): string
    {
        return $this->load($type->keyFile())[0];
    }

    public function kid(MessageType $type): string
    {
        $kid = $this->load($type->keyFile())[1]->get('kid');
        if (!is_string($kid)) {
            throw new RuntimeException('Key without kid');
        }

        return $kid;
    }

    public function publicKeySet(MessageType $type): JWKSet
    {
        return new JWKSet([$this->load($type->keyFile())[1]]);
    }

    /**
     * The private key that no key address publishes. Signs invalid signatures.
     */
    public function roguePrivateKey(): string
    {
        return $this->load(self::ROGUE_FILE)[0];
    }

    /**
     * The public half of the rogue key: an encryption key that the client never registered.
     */
    public function roguePublicKey(): string
    {
        return Jose::publicKeyPem($this->roguePrivateKey());
    }

    /**
     * Load every signing key, including the unpublished key, as the current process user.
     */
    public function assertUsable(): void
    {
        foreach (MessageType::cases() as $type) {
            $this->load($type->keyFile());
        }
        $this->load(self::ROGUE_FILE);
    }

    /**
     * @return array{string, JWK}
     */
    private function load(string $file): array
    {
        if (isset($this->keys[$file])) {
            return $this->keys[$file];
        }
        $pem = @file_get_contents($this->path($file));
        try {
            if ($pem === false) {
                throw new RuntimeException('file not readable');
            }
            $private = @openssl_pkey_get_private($pem);
            $details = $private === false ? false : openssl_pkey_get_details($private);
            if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_RSA) {
                throw new RuntimeException('an RSA private key is required');
            }
            Jose::sign(['check' => true], $pem, []);
            $public = JWKFactory::createFromKey($pem)->toPublic();
        } catch (Throwable $exception) {
            throw new RuntimeException(
                sprintf('Cannot read the mock key %s (run bin/init-keys): %s', $file, $exception->getMessage()),
                0,
                $exception,
            );
        }
        $name = basename($file, '.pem');
        $kid = sprintf('mock-dezi-%s-%s', $name, substr($public->thumbprint('sha256'), 0, 12));

        return $this->keys[$file] = [$pem, new JWK($public->all() + ['kid' => $kid, 'use' => 'sig', 'alg' => 'RS256'])];
    }

    private function path(string $file): string
    {
        return Paths::resolve(Paths::resolve($this->projectDir, $this->keysDirectory), $file);
    }
}
