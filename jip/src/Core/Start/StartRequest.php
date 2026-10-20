<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Start;

/**
 * The fields of EngineBlock's start request that JIP uses (design §12). The names of the organisation
 * attributes are kept; of their values only the binding attribute's is read. Everything else is discarded.
 */
final readonly class StartRequest
{
    /**
     * @param list<string> $attributeNames
     */
    private function __construct(
        public string $userId,
        public string $continueUrl,
        public string $serviceId,
        public string $issuerId,
        public array $attributeNames,
        public BindingInput $binding,
    ) {
    }

    /**
     * Null when the request lacks a used field or `attributes` is not a map of attribute names.
     */
    public static function fromJson(mixed $data, string $bindingAttribute): ?self
    {
        if (!is_array($data)) {
            return null;
        }

        $fields = [];
        foreach (['user_id', 'continue_url', 'service_id', 'issuer_id'] as $name) {
            $value = $data[$name] ?? null;
            if (!is_string($value) || $value === '') {
                return null;
            }
            $fields[$name] = $value;
        }

        // An EngineBlock release without `attributes` must not turn every login into a skip (design §9 item 2).
        $attributes = $data['attributes'] ?? null;
        if (!is_array($attributes)) {
            return null;
        }

        $names = [];
        $byName = [];
        foreach ($attributes as $name => $values) {
            if (!is_string($name) || $name === '') {
                return null;
            }
            $names[] = $name;
            if ($name === $bindingAttribute) {
                $byName[$name] = $values;
            }
        }

        return new self(
            $fields['user_id'],
            $fields['continue_url'],
            $fields['service_id'],
            $fields['issuer_id'],
            $names,
            BindingInput::classify($byName, $bindingAttribute),
        );
    }
}
