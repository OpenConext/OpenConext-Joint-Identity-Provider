<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

use SensitiveParameter;

final readonly class EngineBlockConfiguration
{
    public function __construct(
        #[SensitiveParameter] public string $apiToken,
        public int $callTimeoutSeconds,
        public string $returnUrlPrefix,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'apiToken' => '[redacted]',
            'callTimeoutSeconds' => $this->callTimeoutSeconds,
            'returnUrlPrefix' => $this->returnUrlPrefix,
        ];
    }
}
