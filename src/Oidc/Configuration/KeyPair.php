<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Configuration;

use DateTimeImmutable;
use SensitiveParameter;

/**
 * A client's private key with its certificate, read and checked at startup.
 */
final readonly class KeyPair
{
    public function __construct(
        public string $configPath,
        public string $certificatePem,
        #[SensitiveParameter] private string $privateKeyPem,
        public DateTimeImmutable $notAfter,
        public ?string $kid,
    ) {
    }

    public function privateKeyPem(): string
    {
        return $this->privateKeyPem;
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['configPath' => $this->configPath, 'notAfter' => $this->notAfter, 'kid' => $this->kid];
    }
}
