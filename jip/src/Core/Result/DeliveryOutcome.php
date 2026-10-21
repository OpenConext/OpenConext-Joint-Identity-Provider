<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Result;

use SensitiveParameter;

/**
 * The answer to EngineBlock's result call (design §12, §13): `200` with attributes, or an error status
 * without any attribute.
 */
final readonly class DeliveryOutcome
{
    /**
     * @param array<string, list<string>>|null $attributes
     */
    private function __construct(
        public int $status,
        #[SensitiveParameter] public ?array $attributes,
    ) {
    }

    /**
     * @param non-empty-array<string, list<string>> $attributes
     */
    public static function delivered(array $attributes): self
    {
        return new self(200, $attributes);
    }

    // Unknown, consumed or expired.
    public static function notFound(): self
    {
        return new self(404, null);
    }

    // Not (or no longer) deliverable: not yet completed, failed, or refused at delivery.
    public static function forbidden(): self
    {
        return new self(403, null);
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['status' => $this->status];
    }
}
