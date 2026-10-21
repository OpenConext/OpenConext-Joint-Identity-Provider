<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Cache;

use Closure;
use JsonException;
use RuntimeException;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Validated provider metadata and key sets, kept between requests (design §14). Each entry is read,
 * decided on and written under an exclusive lock, so a refetch decision holds across processes on
 * this node. Entries hold public data only.
 */
final readonly class ProviderCache
{
    public function __construct(
        #[Autowire('%kernel.cache_dir%/jip-provider')] private string $directory,
    ) {
    }

    /**
     * Runs $operation with the current entry under the entry's lock. The operation returns the entry to
     * store (null keeps the current one) and the result to return.
     *
     * @template T
     * @param Closure(array<string, mixed>|null): array{array<string, mixed>|null, T} $operation
     * @return T
     */
    public function update(string $key, Closure $operation): mixed
    {
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0o750, true) && !is_dir($this->directory)) {
            throw new RuntimeException('Cannot create the provider cache directory.');
        }

        $base = $this->directory . '/' . hash('sha256', $key);
        $lock = @fopen($base . '.lock', 'c');
        if ($lock === false) {
            throw new RuntimeException('Cannot open the provider cache lock.');
        }

        try {
            if (!flock($lock, LOCK_EX)) {
                throw new RuntimeException('Cannot lock the provider cache entry.');
            }

            [$next, $result] = $operation(self::read($base . '.json'));
            if ($next !== null) {
                self::write($base . '.json', $next);
            }

            return $result;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    private static function read(string $path): ?array
    {
        $contents = is_file($path) ? @file_get_contents($path) : false;
        if ($contents === false) {
            return null;
        }

        try {
            $data = json_decode($contents, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (!is_array($data)) {
            return null;
        }

        $entry = [];
        foreach ($data as $key => $value) {
            $entry[(string) $key] = $value;
        }

        return $entry;
    }

    /**
     * @param array<string, mixed> $entry
     */
    private static function write(string $path, array $entry): void
    {
        $temporary = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        $json = json_encode($entry, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        if (@file_put_contents($temporary, $json) === false || !@rename($temporary, $path)) {
            @unlink($temporary);
            throw new RuntimeException('Cannot write the provider cache entry.');
        }
    }
}
