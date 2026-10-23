<?php

declare(strict_types=1);

namespace MockDezi\Tests\Functional;

use MockDezi\Tests\Support\JipSimulator;
use MockDezi\Tests\Support\MockDeziFixture;
use MockDezi\Tests\Support\MockDeziTestCase;

/**
 * The successful protocol path, end to end, as JIP will run it (design §3, §14, §15).
 */
final class LoginFlowTest extends MockDeziTestCase
{
    public function test_a_login_yields_a_valid_id_token_and_an_encrypted_sealed_statement(): void
    {
        $tokens = $this->jip->tokens('anna');

        self::assertSame('Bearer', $tokens['token_type']);
        self::assertIsString($tokens['id_token']);
        self::assertIsString($tokens['access_token']);
        self::assertSame('RS256', JipSimulator::header($tokens['id_token'])['alg']);
        $idToken = JipSimulator::verify($tokens['id_token'], $this->jip->keySet('/openid/connect/jwks.json'));
        self::assertNotNull($idToken);
        self::assertSame(JipSimulator::ISSUER, $idToken['iss']);
        self::assertSame(MockDeziFixture::CLIENT_ID, $idToken['aud']);
        self::assertSame($this->jip->nonce, $idToken['nonce']);
        self::assertIsString($idToken['sub']);
        self::assertIsInt($idToken['auth_time']);
        self::assertGreaterThanOrEqual($this->jip->attemptStart, $idToken['auth_time']);
        self::assertLessThanOrEqual(time(), $idToken['auth_time']);
        self::assertIsInt($idToken['exp']);
        self::assertGreaterThan(time(), $idToken['exp']);

        $response = $this->jip->userinfo($tokens['access_token']);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/jwt', $response->headers->get('Content-Type'));
        $jwe = (string) $response->getContent();
        self::assertSame(
            ['alg' => 'RSA-OAEP', 'enc' => 'A256CBC-HS512', 'kid' => 'test-decryption-kid'],
            JipSimulator::header($jwe),
        );

        $envelope = $this->jip->decrypt($jwe);
        $envelopeKeys = $this->jip->keySet('/envelope/jwks.json');
        $envelopeClaims = JipSimulator::verify($envelope, $envelopeKeys);
        self::assertNotNull($envelopeClaims);
        self::assertNull(JipSimulator::verify($envelope, $this->jip->keySet('/openid/connect/jwks.json')));
        self::assertNull(JipSimulator::verify($envelope, $this->jip->keySet('/dezi/jwks.json')));
        self::assertSame('auth.mock-dezi.dev.openconext.local', $envelopeClaims['iss']);
        self::assertSame('test-envelope-audience', $envelopeClaims['aud']);
        self::assertSame('http://eidas.europa.eu/LoA/high', $envelopeClaims['loa_authn']);
        self::assertArrayNotHasKey('sub', $envelopeClaims);
        self::assertSame('d3e2a1c0-0001-4000-8000-000000000001', $envelopeClaims['verklaring_id']);
        self::assertIsString($envelopeClaims['verklaring']);

        $statement = $envelopeClaims['verklaring'];
        self::assertSame('https://mock-dezi.dev.openconext.local/dezi/jwks.json', JipSimulator::header($statement)['jku']);
        $claims = JipSimulator::verify($statement, $this->jip->keySet('/dezi/jwks.json'));
        self::assertNotNull($claims);
        self::assertNull(JipSimulator::verify($statement, $envelopeKeys));
        self::assertSame('abonnee.mock-dezi.dev.openconext.local', $claims['iss']);
        self::assertSame('900000001', $claims['dezi_nummer']);
        self::assertSame('90000001', $claims['abonnee_nummer']);
        self::assertSame('01.000', $claims['rol_code']);
        self::assertNull($claims['voorvoegsel']);
        self::assertSame('http://eidas.europe.eu/LoA/high', $claims['loa_dezi']);
        self::assertSame($envelopeClaims['verklaring_id'], $claims['verklaring_id']);
        self::assertIsInt($claims['exp']);
        self::assertIsInt($claims['nbf']);

        $this->browser->request('GET', '/status/v1/verklaring/' . $claims['verklaring_id']);
        self::assertResponseIsSuccessful();
        self::assertSame(
            ['verklaringId' => 'd3e2a1c0-0001-4000-8000-000000000001', 'status' => 'actief'],
            JipSimulator::json($this->browser->getResponse()),
        );
    }

    public function test_a_person_with_two_profiles_chooses_one_after_logging_in(): void
    {
        $requestId = JipSimulator::requestId($this->jip->authorize());
        $page = $this->jip->login($requestId, 'bram');
        self::assertSame(200, $page->getStatusCode());
        self::assertStringContainsString('bram-ggd-zuid', (string) $page->getContent());

        $code = JipSimulator::callback($this->jip->chooseProfile($requestId, 'bram-ggd-zuid'))['code'];
        $response = $this->jip->token($code);
        $claims = $this->statement(JipSimulator::json($response));

        self::assertSame('900000002', $claims['dezi_nummer']);
        self::assertSame('90000002', $claims['abonnee_nummer']);
        self::assertSame('van der', $claims['voorvoegsel']);
    }

    public function test_another_persons_profile_cannot_be_chosen(): void
    {
        $requestId = JipSimulator::requestId($this->jip->authorize());
        $this->jip->login($requestId, 'bram');

        self::assertSame(400, $this->jip->chooseProfile($requestId, 'anna-ggd-noord')->getStatusCode());
    }

    public function test_a_profile_without_a_role_sends_no_role_claims(): void
    {
        $claims = $this->statement($this->jip->tokens('carla'));

        self::assertArrayNotHasKey('rol_code', $claims);
        self::assertArrayNotHasKey('rol_naam', $claims);
        self::assertArrayNotHasKey('rol_code_bron', $claims);
    }

    public function test_role_00_000_is_sent_as_a_string(): void
    {
        self::assertSame('00.000', $this->statement($this->jip->tokens('dirk'))['rol_code']);
    }

    public function test_the_test_set_role_format_is_kept(): void
    {
        self::assertSame('1.015', $this->statement($this->jip->tokens('bram', profile: 'bram-ggd-noord'))['rol_code']);
    }

    public function test_the_revoked_fixture_answers_the_revoked_status(): void
    {
        $claims = $this->statement($this->jip->tokens('eva'));
        self::assertIsString($claims['verklaring_id']);
        $this->browser->request('GET', '/status/v1/verklaring/' . $claims['verklaring_id']);

        $status = JipSimulator::json($this->browser->getResponse());
        self::assertSame('ingetrokken', $status['status']);
        self::assertSame($claims['verklaring_id'], $status['verklaringId']);
    }

    public function test_the_different_identity_has_another_number_and_subject(): void
    {
        $anna = $this->jip->tokens('anna');
        $frank = (new JipSimulator($this->browser, $this->fixture))->tokens('frank');
        self::assertIsString($anna['id_token']);
        self::assertIsString($frank['id_token']);

        self::assertNotSame(JipSimulator::payload($anna['id_token'])['sub'], JipSimulator::payload($frank['id_token'])['sub']);
        self::assertSame('900000006', $this->statement($frank)['dezi_nummer']);
    }

    public function test_cancel_returns_access_denied_with_the_state(): void
    {
        $requestId = JipSimulator::requestId($this->jip->authorize());

        $callback = JipSimulator::callback($this->jip->login($requestId, '', 'success', 'cancel'));

        self::assertSame('access_denied', $callback['error']);
        self::assertSame($this->jip->state, $callback['state']);
        self::assertArrayNotHasKey('code', $callback);
    }

    public function test_cancel_at_profile_selection_returns_access_denied(): void
    {
        $requestId = JipSimulator::requestId($this->jip->authorize());
        $this->jip->login($requestId, 'bram');

        self::assertSame('access_denied', JipSimulator::callback($this->jip->chooseProfile($requestId, '', 'cancel'))['error']);
    }

    public function test_a_completed_login_page_cannot_be_submitted_again(): void
    {
        $requestId = JipSimulator::requestId($this->jip->authorize());
        $this->jip->login($requestId, 'anna');

        self::assertSame(400, $this->jip->login($requestId, 'anna')->getStatusCode());
    }

    public function test_prompt_login_always_shows_the_login_page_despite_a_session(): void
    {
        $this->jip->code('anna');

        self::assertSame(200, $this->jip->authorize()->getStatusCode());
        self::assertSame(200, $this->jip->authorize(['prompt' => null, 'max_age' => '0'])->getStatusCode());
    }

    public function test_without_prompt_login_the_earlier_session_and_its_auth_time_are_reused(): void
    {
        $first = $this->jip->tokens('anna');
        self::assertIsString($first['id_token']);
        $firstAuthTime = JipSimulator::payload($first['id_token'])['auth_time'];
        sleep(1);

        $callback = JipSimulator::callback($this->jip->authorize(['prompt' => null, 'max_age' => null]));
        $second = JipSimulator::json($this->jip->token($callback['code']));
        self::assertIsString($second['id_token']);

        self::assertSame($firstAuthTime, JipSimulator::payload($second['id_token'])['auth_time']);
    }

    public function test_prompt_none_with_several_profiles_requires_account_selection(): void
    {
        $id = JipSimulator::requestId($this->jip->authorize());
        $this->jip->login($id, 'bram');
        $this->jip->chooseProfile($id, 'bram-ggd-zuid');

        $response = $this->jip->authorize(['prompt' => 'none', 'max_age' => null]);

        self::assertSame(302, $response->getStatusCode());
        $callback = JipSimulator::callback($response);
        self::assertSame('account_selection_required', $callback['error']);
        self::assertSame($this->jip->state, $callback['state']);
    }

    public function test_prompt_none_without_a_session_answers_login_required(): void
    {
        $callback = JipSimulator::callback($this->jip->authorize(['prompt' => 'none', 'max_age' => null]));

        self::assertSame('login_required', $callback['error']);
    }

    /**
     * @param array<string, mixed> $tokens
     * @return array<string, mixed>
     */
    private function statement(array $tokens): array
    {
        self::assertIsString($tokens['access_token']);
        $envelope = JipSimulator::payload($this->jip->decrypt((string) $this->jip->userinfo($tokens['access_token'])->getContent()));
        self::assertIsString($envelope['verklaring']);

        return JipSimulator::payload($envelope['verklaring']);
    }
}
