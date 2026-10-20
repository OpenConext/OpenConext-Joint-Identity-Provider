<?php

declare(strict_types=1);

namespace MockDezi\Http;

use MockDezi\Configuration\ConfigurationLoader;
use MockDezi\Fixture\FixtureRepository;
use MockDezi\Key\KeyRing;
use MockDezi\Scenario\Scenario;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Throwable;

/**
 * An overview page for developers and a health check for the container.
 */
final readonly class IndexController
{
    public function __construct(
        private ConfigurationLoader $loader,
        private FixtureRepository $fixtures,
        private KeyRing $keys,
    ) {
    }

    #[Route('/health', name: 'mock_dezi_health', methods: ['GET'])]
    public function health(): Response
    {
        try {
            $this->loader->load();
            $this->fixtures->persons();
            $this->keys->assertUsable();
        } catch (Throwable) {
            return Responses::json(['status' => 'DOWN'], Response::HTTP_SERVICE_UNAVAILABLE);
        }

        return Responses::json(['status' => 'UP']);
    }

    #[Route('/', name: 'mock_dezi_index', methods: ['GET'])]
    public function index(): Response
    {
        $configuration = $this->loader->load();
        $persons = '';
        foreach ($this->fixtures->persons() as $person) {
            foreach ($person->profiles as $profile) {
                $persons .= sprintf(
                    '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td>'
                    . '<td>%s</td></tr>',
                    Html::e($person->id),
                    Html::e($person->deziNummer),
                    Html::e($profile->id),
                    Html::e($profile->abonneeNummer),
                    Html::e($profile->rolCode ?? '(none)'),
                    Html::e($profile->verklaringId),
                    Html::e($profile->status->value),
                );
            }
        }
        $scenarios = '';
        foreach (Scenario::cases() as $scenario) {
            $scenarios .= sprintf(
                '<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>',
                Html::e($scenario->step()),
                Html::e($scenario->value),
                $scenario->isAccepted() ? 'accept' : 'refuse',
                Html::e($scenario->description()),
            );
        }

        return Html::page('Mock DEZI provider', sprintf(
            '<p>Issuer <code>%s</code>. Discovery: <code>/.well-known/openid-configuration</code>. '
            . 'Scenario selection and reset: see the README; machine-readable list at '
            . '<code>GET /mock/scenarios</code>, '
            . 'current state at <code>GET /mock/state</code>.</p>'
            . '<p>All persons, numbers and statements are PROVISIONAL synthetic fixtures, not DEZI data.</p>'
            . '<h2>Persons and profiles</h2><table><tr><th>Person</th><th>DEZI number</th><th>Profile</th>'
            . '<th>Subscriber</th><th>Role code</th><th>verklaring_id</th><th>Register status</th></tr>%s</table>'
            . '<h2>Scenarios</h2><table><tr><th>Step</th><th>Name</th><th>JIP</th><th>Effect</th></tr>%s</table>',
            Html::e($configuration->issuer),
            $persons,
            $scenarios,
        ));
    }
}
