<?php

declare(strict_types=1);

namespace JointIdentityProvider\Configuration\Reader;

/**
 * Collects every configuration problem so one run reports all of them.
 * Messages name configuration paths only, never configured values.
 */
final class ConfigurationErrors
{
    /** @var list<string> */
    private array $errors = [];

    public function add(string $path, string $message): void
    {
        $this->errors[] = sprintf('%s: %s', $path === '' ? '(root)' : $path, $message);
    }

    public function isEmpty(): bool
    {
        return $this->errors === [];
    }

    /**
     * @return list<string>
     */
    public function all(): array
    {
        return $this->errors;
    }
}
