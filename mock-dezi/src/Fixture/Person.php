<?php

declare(strict_types=1);

namespace MockDezi\Fixture;

/**
 * A synthetic person in the mock's register. PROVISIONAL fixture data (fixtures/profiles.yaml).
 */
final readonly class Person
{
    /**
     * @param list<Profile> $profiles
     */
    public function __construct(
        public string $id,
        public string $description,
        public string $deziNummer,
        public string $voorletters,
        public ?string $voorvoegsel,
        public string $achternaam,
        public array $profiles,
    ) {
    }

    public function profile(string $profileId): ?Profile
    {
        foreach ($this->profiles as $profile) {
            if ($profile->id === $profileId) {
                return $profile;
            }
        }

        return null;
    }

    public function displayName(): string
    {
        return trim(sprintf('%s %s %s', $this->voorletters, $this->voorvoegsel ?? '', $this->achternaam));
    }
}
