<?php

declare(strict_types=1);

namespace MockDezi\Tests\Functional;

use MockDezi\Tests\Support\JipSimulator;
use MockDezi\Tests\Support\MockDeziTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Discovery, key sets, the authorisation request checks, endpoint modes, statement selection and reset.
 */
final class EndpointTest extends MockDeziTestCase
{
    public function test_discovery_advertises_the_mock_endpoints_and_private_key_jwt(): void
    {
        $this->browser->request('GET', '/.well-known/openid-configuration');
        $metadata = JipSimulator::json($this->browser->getResponse());

        self::assertSame(JipSimulator::ISSUER, $metadata['issuer']);
        self::assertSame(JipSimulator::TOKEN_ENDPOINT, $metadata['token_endpoint']);
        self::assertSame(JipSimulator::ISSUER . '/openid/connect/jwks.json', $metadata['jwks_uri']);
        self::assertSame(['none', 'private_key_jwt'], $metadata['token_endpoint_auth_methods_supported']);
        self::assertSame(['S256'], $metadata['code_challenge_methods_supported']);
        self::assertSame(['RS256'], $metadata['id_token_signing_alg_values_supported']);
        self::assertSame(['pairwise'], $metadata['subject_types_supported']);
    }

    public function test_each_message_type_has_its_own_public_key_set(): void
    {
        $kids = [];
        foreach (['/openid/connect/jwks.json', '/envelope/jwks.json', '/dezi/jwks.json'] as $path) {
            $this->browser->request('GET', $path);
            $set = JipSimulator::json($this->browser->getResponse());
            self::assertIsArray($set['keys']);
            self::assertCount(1, $set['keys']);
            $key = $set['keys'][0];
            self::assertIsArray($key);
            self::assertSame(['RSA', 'sig', 'RS256'], [$key['kty'], $key['use'], $key['alg']]);
            self::assertArrayNotHasKey('d', $key);
            self::assertArrayNotHasKey('p', $key);
            self::assertIsString($key['kid']);
            $kids[] = $key['kid'];
        }

        self::assertCount(3, array_unique($kids));
    }

    public function test_discovery_modes(): void
    {
        $this->admin('PUT', '/mock/endpoints/discovery', ['mode' => 'auth_methods_none_only']);
        $this->browser->request('GET', '/.well-known/openid-configuration');
        self::assertSame(['none'], JipSimulator::json($this->browser->getResponse())['token_endpoint_auth_methods_supported']);

        $this->admin('PUT', '/mock/endpoints/discovery', ['mode' => 'wrong_jwks_uri']);
        $this->browser->request('GET', '/.well-known/openid-configuration');
        self::assertSame(JipSimulator::ISSUER . '/dezi/jwks.json', JipSimulator::json($this->browser->getResponse())['jwks_uri']);

        $this->admin('PUT', '/mock/endpoints/discovery', ['mode' => 'without_auth_methods']);
        $this->browser->request('GET', '/.well-known/openid-configuration');
        self::assertArrayNotHasKey('token_endpoint_auth_methods_supported', JipSimulator::json($this->browser->getResponse()));
    }

    public function test_a_key_set_redirects_to_another_message_types_address(): void
    {
        $this->admin('PUT', '/mock/endpoints/jwks_statement', ['mode' => 'redirect']);
        $this->browser->request('GET', '/dezi/jwks.json');

        self::assertResponseRedirects(JipSimulator::ISSUER . '/openid/connect/jwks.json?redirected=1', 302);
    }

    public function test_endpoint_unavailability_and_its_reset(): void
    {
        $this->admin('PUT', '/mock/endpoints/token', ['mode' => 'unavailable']);
        $code = $this->jip->code();
        $response = $this->jip->token($code);
        self::assertSame([503, '30'], [$response->getStatusCode(), $response->headers->get('Retry-After')]);

        $this->admin('PUT', '/mock/endpoints/token', ['mode' => 'available']);
        self::assertSame(200, $this->jip->token($code)->getStatusCode());
    }

    public function test_status_endpoint_modes_apply_to_every_statement(): void
    {
        $this->admin('PUT', '/mock/endpoints/status', ['mode' => 'invalid_body']);
        $this->browser->request('GET', '/status/v1/verklaring/d3e2a1c0-0001-4000-8000-000000000001');
        self::assertNull(json_decode((string) $this->browser->getResponse()->getContent(), true));

        $this->admin('PUT', '/mock/endpoints/status', ['mode' => 'timeout']);
        $start = microtime(true);
        $this->browser->request('GET', '/status/v1/verklaring/d3e2a1c0-0001-4000-8000-000000000001');
        self::assertGreaterThanOrEqual(1.0, microtime(true) - $start);
        self::assertResponseIsSuccessful();
    }

    public function test_a_statement_can_be_revoked_after_login_and_unknown_ids_answer_404(): void
    {
        $id = 'd3e2a1c0-0001-4000-8000-000000000001';
        $this->admin('PUT', '/mock/statements/' . $id, ['behaviour' => 'revoked']);
        $this->browser->request('GET', '/status/v1/verklaring/' . $id);
        self::assertSame('ingetrokken', JipSimulator::json($this->browser->getResponse())['status']);

        $this->browser->request('GET', '/status/v1/verklaring/00000000-0000-4000-8000-000000000000');
        self::assertResponseStatusCodeSame(404);

        $this->admin('POST', '/mock/reset');
        $this->browser->request('GET', '/status/v1/verklaring/' . $id);
        self::assertSame('actief', JipSimulator::json($this->browser->getResponse())['status']);
    }

    public function test_the_default_scenario_preselects_the_login_page_and_applies_without_a_choice(): void
    {
        $this->admin('PUT', '/mock/default-scenario', ['scenario' => 'cancel']);
        $page = $this->jip->authorize();
        self::assertStringContainsString('value="cancel" selected', (string) $page->getContent());

        $callback = JipSimulator::callback($this->jip->login(JipSimulator::requestId($page), 'anna', ''));

        self::assertSame('access_denied', $callback['error']);
    }

    public function test_admin_changes_need_a_json_body_and_known_values(): void
    {
        $this->browser->request('PUT', '/mock/default-scenario', ['scenario' => 'cancel']);
        self::assertResponseStatusCodeSame(415);

        $this->admin('PUT', '/mock/default-scenario', ['scenario' => 'unknown']);
        self::assertResponseStatusCodeSame(400);

        $this->admin('PUT', '/mock/endpoints/token', ['mode' => 'wrong_jwks_uri']);
        self::assertResponseStatusCodeSame(400);

        $this->admin('PUT', '/mock/statements/x', ['behaviour' => 'gone']);
        self::assertResponseStatusCodeSame(400);
    }

    public function test_the_links_inside_the_statement_are_counted_and_refused(): void
    {
        $this->browser->request('GET', '/statement-link/revocatie/d3e2a1c0-0001-4000-8000-000000000001');
        self::assertResponseStatusCodeSame(410);

        $this->browser->request('GET', '/mock/state');
        self::assertSame(
            ['revocatie/d3e2a1c0-0001-4000-8000-000000000001' => 1],
            JipSimulator::json($this->browser->getResponse())['statement_link_calls'],
        );
    }

    public function test_an_unknown_client_or_redirect_uri_gets_an_error_page_and_no_redirect(): void
    {
        self::assertSame(400, $this->jip->authorize(['client_id' => 'unknown'])->getStatusCode());
        self::assertSame(400, $this->jip->authorize(['redirect_uri' => 'https://evil.example/cb'])->getStatusCode());
    }

    /**
     * @return iterable<string, array{array<string, string|null>, string}>
     */
    public static function invalidAuthorizationRequests(): iterable
    {
        yield 'no PKCE' => [['code_challenge' => null, 'code_challenge_method' => null], 'invalid_request'];
        yield 'PKCE plain' => [['code_challenge_method' => 'plain'], 'invalid_request'];
        yield 'no nonce' => [['nonce' => null], 'invalid_request'];
        yield 'implicit flow' => [['response_type' => 'id_token'], 'unsupported_response_type'];
        yield 'no openid scope' => [['scope' => 'profile'], 'invalid_scope'];
        yield 'extra scope' => [['scope' => 'openid profile'], 'invalid_scope'];
        yield 'negative max_age' => [['max_age' => '-1'], 'invalid_request'];
        yield 'form_post' => [['response_mode' => 'form_post'], 'invalid_request'];
    }

    /**
     * @param array<string, string|null> $override
     */
    #[DataProvider('invalidAuthorizationRequests')]
    public function test_an_invalid_authorization_request_is_answered_at_the_callback(array $override, string $error): void
    {
        $callback = JipSimulator::callback($this->jip->authorize($override));

        self::assertSame([$error, $this->jip->state], [$callback['error'], $callback['state']]);
    }

    public function test_health_and_overview_page(): void
    {
        $this->browser->request('GET', '/health');
        self::assertResponseIsSuccessful();

        $this->browser->request('GET', '/');
        self::assertResponseIsSuccessful();
        self::assertStringContainsString('PROVISIONAL', (string) $this->browser->getResponse()->getContent());
        self::assertStringContainsString('statement_jku_other_address', (string) $this->browser->getResponse()->getContent());
    }
}
