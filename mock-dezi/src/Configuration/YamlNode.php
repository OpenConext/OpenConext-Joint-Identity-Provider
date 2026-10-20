<?php

declare(strict_types=1);

namespace MockDezi\Configuration;

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * A typed view on one value of a YAML file. Every getter refuses a missing or mistyped value with its path.
 */
final readonly class YamlNode
{
    private function __construct(
        private mixed $value,
        private string $path,
        private bool $present,
    ) {
    }

    public static function fromFile(string $file): self
    {
        if (!is_file($file)) {
            throw new InvalidMockConfiguration(sprintf('%s: file not found', $file));
        }
        try {
            $value = Yaml::parseFile($file);
        } catch (ParseException $exception) {
            throw new InvalidMockConfiguration(sprintf('%s: %s', $file, $exception->getMessage()), 0, $exception);
        }

        return new self($value, $file, true);
    }

    public function path(): string
    {
        return $this->path;
    }

    /**
     * @param list<string> $allowed
     */
    public function allowOnly(array $allowed): void
    {
        foreach (array_keys($this->mapValue()) as $key) {
            if (!in_array((string) $key, $allowed, true)) {
                throw new InvalidMockConfiguration(sprintf('%s.%s: unknown setting', $this->path, $key));
            }
        }
    }

    public function get(string $key): self
    {
        $map = $this->mapValue();

        return new self($map[$key] ?? null, $this->path . '.' . $key, array_key_exists($key, $map));
    }

    public function string(): string
    {
        if (!is_string($this->value) || $this->value === '') {
            throw $this->error('must be a non-empty string');
        }

        return $this->value;
    }

    public function nullableString(): ?string
    {
        if (!$this->present) {
            throw $this->error('is required (use ~ for none)');
        }

        return $this->value === null ? null : $this->string();
    }

    public function positiveInt(): int
    {
        if (!is_int($this->value) || $this->value < 1) {
            throw $this->error('must be a positive integer');
        }

        return $this->value;
    }

    /**
     * @return list<string>
     */
    public function stringList(): array
    {
        if (!is_array($this->value) || !array_is_list($this->value)) {
            throw $this->error('must be a list');
        }

        return array_map(
            fn (mixed $item): string => is_string($item) && $item !== ''
                ? $item
                : throw $this->error('must hold non-empty strings only'),
            $this->value,
        );
    }

    /**
     * @return array<string, self>
     */
    public function children(): array
    {
        $children = [];
        foreach ($this->mapValue() as $key => $value) {
            $children[(string) $key] = new self($value, $this->path . '.' . $key, true);
        }

        return $children;
    }

    /**
     * @return list<self>
     */
    public function items(): array
    {
        if (!is_array($this->value) || !array_is_list($this->value)) {
            throw $this->error('must be a list');
        }
        $items = [];
        foreach ($this->value as $index => $value) {
            $items[] = new self($value, sprintf('%s[%d]', $this->path, $index), true);
        }

        return $items;
    }

    /**
     * @param list<string> $choices
     */
    public function choice(array $choices): string
    {
        $value = $this->string();
        if (!in_array($value, $choices, true)) {
            throw $this->error(sprintf('must be one of %s', implode(', ', $choices)));
        }

        return $value;
    }

    public function error(string $message): InvalidMockConfiguration
    {
        return new InvalidMockConfiguration(sprintf('%s: %s', $this->path, $message));
    }

    /**
     * @return array<mixed>
     */
    private function mapValue(): array
    {
        if (!is_array($this->value) || ($this->value !== [] && array_is_list($this->value))) {
            throw $this->error(sprintf('must be a map, got %s', get_debug_type($this->value)));
        }

        return $this->value;
    }
}
