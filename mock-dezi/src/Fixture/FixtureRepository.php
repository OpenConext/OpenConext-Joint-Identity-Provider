<?php

declare(strict_types=1);

namespace MockDezi\Fixture;

use MockDezi\Configuration\InvalidMockConfiguration;
use MockDezi\Configuration\Paths;
use MockDezi\Configuration\YamlNode;
use MockDezi\Scenario\StatementBehaviour;

/**
 * The synthetic persons and profiles of fixtures/profiles.yaml.
 */
final class FixtureRepository
{
    public const string UUID_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/';

    /** @var array<string, Person>|null */
    private ?array $persons = null;

    public function __construct(
        private readonly string $projectDir,
        private readonly string $fixturesFile,
    ) {
    }

    /**
     * @return array<string, Person>
     */
    public function persons(): array
    {
        return $this->persons ??= $this->read();
    }

    public function person(string $personId): ?Person
    {
        return $this->persons()[$personId] ?? null;
    }

    public function profileByVerklaringId(string $verklaringId): ?Profile
    {
        foreach ($this->persons() as $person) {
            foreach ($person->profiles as $profile) {
                if ($profile->verklaringId === $verklaringId) {
                    return $profile;
                }
            }
        }

        return null;
    }

    /**
     * @return array<string, Person>
     */
    private function read(): array
    {
        $root = YamlNode::fromFile(Paths::resolve($this->projectDir, $this->fixturesFile));
        $root->allowOnly(['persons']);
        $persons = [];
        $statementIds = [];
        $profileIds = [];
        foreach ($root->get('persons')->children() as $personId => $node) {
            $node->allowOnly(['description', 'dezi_nummer', 'voorletters', 'voorvoegsel', 'achternaam', 'profiles']);
            $profiles = [];
            foreach ($node->get('profiles')->items() as $profileNode) {
                $profile = $this->profile($profileNode);
                if (isset($statementIds[$profile->verklaringId]) || isset($profileIds[$profile->id])) {
                    throw $profileNode->error('profile id and verklaring_id must be unique');
                }
                $statementIds[$profile->verklaringId] = true;
                $profileIds[$profile->id] = true;
                $profiles[] = $profile;
            }
            if ($profiles === []) {
                throw $node->get('profiles')->error('must hold at least one profile');
            }
            $persons[$personId] = new Person(
                id: $personId,
                description: $node->get('description')->string(),
                deziNummer: $node->get('dezi_nummer')->string(),
                voorletters: $node->get('voorletters')->string(),
                voorvoegsel: $node->get('voorvoegsel')->nullableString(),
                achternaam: $node->get('achternaam')->string(),
                profiles: $profiles,
            );
        }
        if ($persons === []) {
            throw new InvalidMockConfiguration($root->path() . ': no persons');
        }

        return $persons;
    }

    private function profile(YamlNode $node): Profile
    {
        $node->allowOnly([
            'id', 'label', 'verklaring_id', 'abonnee_nummer', 'abonnee_naam', 'rol_code', 'rol_naam',
            'rol_code_bron', 'status',
        ]);
        $verklaringId = $node->get('verklaring_id')->string();
        if (preg_match(self::UUID_PATTERN, $verklaringId) !== 1) {
            throw $node->get('verklaring_id')->error('must be a lower-case UUID');
        }
        $status = StatementBehaviour::from($node->get('status')->choice(StatementBehaviour::registerValues()));

        $rolCode = $node->get('rol_code')->nullableString();
        $rolNaam = $node->get('rol_naam')->nullableString();
        $rolCodeBron = $node->get('rol_code_bron')->nullableString();
        if (($rolCode === null) !== ($rolNaam === null) || ($rolCode === null) !== ($rolCodeBron === null)) {
            throw $node->error('rol_code, rol_naam and rol_code_bron must all be strings or all be null');
        }

        return new Profile(
            id: $node->get('id')->string(),
            label: $node->get('label')->string(),
            verklaringId: $verklaringId,
            abonneeNummer: $node->get('abonnee_nummer')->string(),
            abonneeNaam: $node->get('abonnee_naam')->string(),
            rolCode: $rolCode,
            rolNaam: $rolNaam,
            rolCodeBron: $rolCodeBron,
            status: $status,
        );
    }
}
