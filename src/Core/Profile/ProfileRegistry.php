<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Profile;

use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;

final readonly class ProfileRegistry
{
    /** @var array<string, ProviderProfile> */
    private array $profiles;

    /**
     * @param iterable<ProviderProfile> $profiles
     */
    public function __construct(#[AutowireIterator(ProviderProfile::TAG)] iterable $profiles)
    {
        $byName = [];
        foreach ($profiles as $profile) {
            $byName[$profile->name()] = $profile;
        }
        $this->profiles = $byName;
    }

    public function get(string $name): ?ProviderProfile
    {
        return $this->profiles[$name] ?? null;
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->profiles);
    }
}
