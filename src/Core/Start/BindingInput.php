<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Start;

use SensitiveParameter;

/**
 * The binding attribute as the start call carries it (design §4). Only the organisation's attribute decides.
 */
final readonly class BindingInput
{
    private function __construct(
        public BindingStatus $status,
        #[SensitiveParameter] public string $value,
    ) {
    }

    /**
     * Absent, an empty list or one empty string: absent. Exactly one non-empty string that is not only
     * whitespace: that value. Anything else is malformed.
     *
     * @param array<string, mixed> $attributes
     */
    public static function classify(array $attributes, string $attributeName): self
    {
        if (!array_key_exists($attributeName, $attributes)) {
            return new self(BindingStatus::Absent, '');
        }

        $values = $attributes[$attributeName];
        if (!is_array($values)) {
            return new self(BindingStatus::Malformed, '');
        }
        if ($values === []) {
            return new self(BindingStatus::Absent, '');
        }
        if (count($values) !== 1) {
            return new self(BindingStatus::Malformed, '');
        }

        $value = reset($values);
        if (!is_string($value)) {
            return new self(BindingStatus::Malformed, '');
        }
        if ($value === '') {
            return new self(BindingStatus::Absent, '');
        }
        if (trim($value) === '') {
            return new self(BindingStatus::Malformed, '');
        }

        return new self(BindingStatus::Single, $value);
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['status' => $this->status];
    }
}
