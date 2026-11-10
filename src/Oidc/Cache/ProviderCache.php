<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Cache;

use Closure;
use Psr\Cache\CacheItemPoolInterface;
use RuntimeException;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Lock\LockFactory;

/**
 * Public provider metadata and keys. The pool and lock store must cover the same processes: each
 * entry is read, decided on and saved under its lock, including the provider request when needed.
 */
final readonly class ProviderCache
{
    public function __construct(
        #[Autowire(service: 'cache.jip_provider')] private CacheItemPoolInterface $pool,
        #[Autowire(service: 'lock.jip_provider.factory', lazy: true)] private LockFactory $locks,
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
        $id = hash('sha256', $key);
        $lock = $this->locks->createLock('jip-provider.' . $id);
        if (!$lock->acquire(true)) {
            throw new RuntimeException('Cannot lock the provider cache entry.');
        }

        try {
            $item = $this->pool->getItem($id);
            [$next, $result] = $operation($item->isHit() ? self::entry($item->get()) : null);
            if ($next !== null) {
                // Freshness and failed-fetch backoff use the approved policy and injected clock in
                // MetadataProvider/KeyResolver, rather than a second, independent pool lifetime.
                $item->set($next)->expiresAfter(null);
                if (!$this->pool->save($item)) {
                    throw new RuntimeException('Cannot save the provider cache entry.');
                }
            }

            return $result;
        } finally {
            $lock->release();
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    private static function entry(mixed $value): ?array
    {
        if (!is_array($value)) {
            return null;
        }

        $entry = [];
        foreach ($value as $key => $item) {
            $entry[(string) $key] = $item;
        }

        return $entry;
    }
}
