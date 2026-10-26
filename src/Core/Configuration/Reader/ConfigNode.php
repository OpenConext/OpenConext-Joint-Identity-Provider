<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration\Reader;

/**
 * A path-aware view on one value of the parsed configuration. Every accessor validates the value,
 * reports a problem under the node's path and returns null when the value is unusable.
 */
final readonly class ConfigNode
{
    private function __construct(
        private mixed $value,
        private bool $present,
        public string $path,
        private ConfigurationErrors $errors,
    ) {
    }

    public static function root(mixed $value, ConfigurationErrors $errors): self
    {
        return new self($value, true, '', $errors);
    }

    public function isPresent(): bool
    {
        return $this->present;
    }

    public function get(string|int $key): self
    {
        $present = is_array($this->value) && array_key_exists($key, $this->value);
        $value = $present ? $this->value[$key] : null;

        return new self($value, $present, self::joinPath($this->path, $key), $this->errors);
    }

    public function error(string $message): void
    {
        $this->errors->add($this->path, $message);
    }

    /**
     * A required map with string keys. Children are read with get() or entries().
     */
    public function requireMap(): bool
    {
        if (!$this->present) {
            $this->error('is missing');

            return false;
        }

        if (!is_array($this->value) || ($this->value !== [] && array_is_list($this->value))) {
            $this->error('must be a map');

            return false;
        }

        foreach (array_keys($this->value) as $key) {
            if (!is_string($key) || $key === '') {
                $this->error('must have non-empty string keys');

                return false;
            }
        }

        return true;
    }

    /**
     * Reports keys that are not in $allowed. Call after requireMap() succeeded.
     */
    public function allowOnly(string ...$allowed): void
    {
        if (!is_array($this->value)) {
            return;
        }

        foreach (array_keys($this->value) as $key) {
            if (!in_array($key, $allowed, true)) {
                $this->errors->add(self::joinPath($this->path, $key), 'is not a known setting');
            }
        }
    }

    /**
     * The children of a map that passed requireMap().
     *
     * @return array<string, self>
     */
    public function entries(): array
    {
        if (!is_array($this->value)) {
            return [];
        }

        $entries = [];
        foreach (array_keys($this->value) as $key) {
            $entries[(string) $key] = $this->get($key);
        }

        return $entries;
    }

    /**
     * A required list; the items are returned as nodes.
     *
     * @return list<self>|null
     */
    public function requireList(): ?array
    {
        if (!$this->present) {
            $this->error('is missing');

            return null;
        }

        if (!is_array($this->value) || !array_is_list($this->value)) {
            $this->error('must be a list');

            return null;
        }

        $items = [];
        foreach (array_keys($this->value) as $index) {
            $items[] = $this->get($index);
        }

        return $items;
    }

    /**
     * A list of unique, non-empty strings.
     *
     * @return list<string>|null
     */
    public function requireUniqueStringList(): ?array
    {
        $items = $this->requireList();
        if ($items === null) {
            return null;
        }

        $values = [];
        $valid = true;
        foreach ($items as $item) {
            $value = $item->requireString();
            if ($value === null) {
                $valid = false;
            } elseif (in_array($value, $values, true)) {
                $item->error('is a duplicate entry');
                $valid = false;
            } else {
                $values[] = $value;
            }
        }

        return $valid ? $values : null;
    }

    public function requireString(): ?string
    {
        if (!$this->present) {
            $this->error('is missing');

            return null;
        }

        return $this->stringValue();
    }

    public function optionalString(): ?string
    {
        return $this->present ? $this->stringValue() : null;
    }

    public function requireHttpsUrl(): ?string
    {
        $value = $this->requireString();
        if ($value === null) {
            return null;
        }

        if (!self::isAbsoluteHttpsUrl($value)) {
            $this->error('must be an absolute https URL');

            return null;
        }

        return $value;
    }

    public function requirePositiveInt(): ?int
    {
        if (!$this->present) {
            $this->error('is missing');

            return null;
        }

        if (!is_int($this->value) || $this->value <= 0) {
            $this->error('must be a positive integer');

            return null;
        }

        return $this->value;
    }

    public function optionalNonNegativeInt(): ?int
    {
        if (!$this->present) {
            return null;
        }

        if (!is_int($this->value) || $this->value < 0) {
            $this->error('must be a non-negative integer');

            return null;
        }

        return $this->value;
    }

    public function requireBool(): ?bool
    {
        if (!$this->present) {
            $this->error('is missing');

            return null;
        }

        if (!is_bool($this->value)) {
            $this->error('must be true or false');

            return null;
        }

        return $this->value;
    }

    public static function isAbsoluteHttpsUrl(string $value): bool
    {
        if (preg_match('/\s/', $value) === 1) {
            return false;
        }

        $parts = parse_url($value);

        return is_array($parts)
            && ($parts['scheme'] ?? null) === 'https'
            && ($parts['host'] ?? '') !== ''
            && !isset($parts['user'])
            && !isset($parts['pass']);
    }

    private function stringValue(): ?string
    {
        if (!is_string($this->value) || trim($this->value) === '') {
            $this->error('must be a non-empty string');

            return null;
        }

        return $this->value;
    }

    public static function joinPath(string $parent, string|int $key): string
    {
        if (is_int($key)) {
            return sprintf('%s[%d]', $parent, $key);
        }

        $segment = preg_match('/^[A-Za-z0-9_]+\z/', $key) === 1 ? $key : sprintf("['%s']", $key);

        if ($parent === '') {
            return $segment;
        }

        return str_starts_with($segment, '[') ? $parent . $segment : $parent . '.' . $segment;
    }
}
