<?php

declare(strict_types=1);

namespace MockDezi\Tests\Functional;

use MockDezi\Message\Jose;
use MockDezi\Tests\Support\JipSimulator;
use MockDezi\Tests\Support\MockDeziFixture;
use MockDezi\Tests\Support\MockDeziTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The token endpoint: private_key_jwt, the single-use code and PKCE S256 (design §14, §18 "Client authentication").
 */
final class TokenEndpointTest extends MockDeziTestCase
{
    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidAssertionClaims(): iterable
    {
        yield 'another iss' => [['iss' => 'another-client'], 'iss and sub'];
        yield 'another sub' => [['sub' => 'another-client'], 'iss and sub'];
        yield 'aud is the issuer' => [['aud' => JipSimulator::ISSUER], 'aud'];
        yield 'aud with an extra value' => [['aud' => [JipSimulator::TOKEN_ENDPOINT, 'x']], 'aud'];
        yield 'expired' => [['iat' => time() - 400, 'exp' => time() - 120], 'expired'];
        yield 'lifetime too long' => [['exp' => time() + 3600], 'exp - iat'];
        yield 'iat in the future' => [['iat' => time() + 600, 'exp' => time() + 660], 'iat'];
        yield 'no jti' => [['jti' => ''], 'jti'];
        yield 'exp as string' => [['exp' => (string) (time() + 60)], 'numbers'];
    }

    /**
     * @param array<string, mixed> $claims
     */
    #[DataProvider('invalidAssertionClaims')]
    public function test_an_invalid_client_assertion_is_refused_with_invalid_client(array $claims, string $reason): void
    {
        $code = $this->jip->code();

        $response = $this->jip->token($code, ['client_assertion' => $this->jip->assertion($claims)]);

        $this->assertInvalidClient($response->getStatusCode(), JipSimulator::json($response), $reason);
    }

    public function test_a_request_without_an_assertion_is_refused(): void
    {
        $response = $this->jip->token($this->jip->code(), ['client_assertion' => null, 'client_assertion_type' => null]);

        $this->assertInvalidClient($response->getStatusCode(), JipSimulator::json($response), 'client_assertion_type');
    }

    public function test_an_assertion_signed_with_an_unregistered_key_is_refused(): void
    {
        $assertion = $this->jip->assertion(key: $this->fixture->otherSigningKey);

        $response = $this->jip->token($this->jip->code(), ['client_assertion' => $assertion]);

        $this->assertInvalidClient($response->getStatusCode(), JipSimulator::json($response), 'signature');
    }

    public function test_an_assertion_naming_an_unregistered_certificate_is_refused(): void
    {
        $assertion = $this->jip->assertion(
            key: $this->fixture->otherSigningKey,
            certificate: $this->fixture->otherSigningCertificate,
        );

        $response = $this->jip->token($this->jip->code(), ['client_assertion' => $assertion]);

        $this->assertInvalidClient($response->getStatusCode(), JipSimulator::json($response), 'x5t#S256');
    }

    public function test_an_assertion_without_x5t_s256_is_refused(): void
    {
        $assertion = $this->jip->assertion(header: ['kid' => 'test-signing']);

        $response = $this->jip->token($this->jip->code(), ['client_assertion' => $assertion]);

        $this->assertInvalidClient($response->getStatusCode(), JipSimulator::json($response), 'x5t#S256');
    }

    public function test_a_repeated_jti_is_refused_and_the_code_survives_a_refused_authentication(): void
    {
        $code = $this->jip->code();
        $assertion = $this->jip->assertion(['jti' => 'fixed-jti']);
        $first = $this->jip->token($code, ['client_assertion' => $assertion, 'code_verifier' => str_repeat('a', 43)]);
        self::assertSame('invalid_grant', JipSimulator::json($first)['error']);

        $secondCode = $this->jip->code();
        $second = $this->jip->token($secondCode, ['client_assertion' => $assertion]);

        $this->assertInvalidClient($second->getStatusCode(), JipSimulator::json($second), 'jti');
        self::assertSame(200, $this->jip->token($secondCode)->getStatusCode());
    }

    public function test_both_registered_signing_certificates_are_accepted_during_a_replacement(): void
    {
        $this->start(new MockDeziFixture(registerOtherSigningKey: true));
        $old = $this->jip->token($this->jip->code());
        $new = $this->jip->token($this->jip->code(), ['client_assertion' => $this->jip->assertion(
            key: $this->fixture->otherSigningKey,
            certificate: $this->fixture->otherSigningCertificate,
        )]);

        self::assertSame(200, $old->getStatusCode());
        self::assertSame(200, $new->getStatusCode());
    }

    public function test_a_none_client_authenticates_without_an_assertion_and_is_refused_with_one(): void
    {
        $jip = new JipSimulator($this->browser, $this->fixture, MockDeziFixture::NONE_CLIENT_ID);
        $withAssertion = $jip->token($jip->code());
        $without = $jip->token($jip->code(), ['client_assertion' => null, 'client_assertion_type' => null]);

        $this->assertInvalidClient($withAssertion->getStatusCode(), JipSimulator::json($withAssertion), 'none');
        self::assertSame(200, $without->getStatusCode());
    }

    public function test_a_code_is_single_use(): void
    {
        $code = $this->jip->code();
        self::assertSame(200, $this->jip->token($code)->getStatusCode());

        $replay = $this->jip->token($code);

        self::assertSame(400, $replay->getStatusCode());
        self::assertSame('invalid_grant', JipSimulator::json($replay)['error']);
    }

    public function test_a_wrong_pkce_verifier_consumes_the_code(): void
    {
        $code = $this->jip->code();
        $wrong = $this->jip->token($code, ['code_verifier' => Jose::randomToken()]);
        $right = $this->jip->token($code);

        self::assertSame('invalid_grant', JipSimulator::json($wrong)['error']);
        self::assertSame('invalid_grant', JipSimulator::json($right)['error']);
    }

    public function test_another_redirect_uri_is_refused(): void
    {
        $response = $this->jip->token($this->jip->code(), ['redirect_uri' => 'https://jip.dev.openconext.local/other']);

        self::assertSame('invalid_grant', JipSimulator::json($response)['error']);
    }

    public function test_another_grant_type_is_refused(): void
    {
        $response = $this->jip->token($this->jip->code(), ['grant_type' => 'refresh_token']);

        self::assertSame('unsupported_grant_type', JipSimulator::json($response)['error']);
    }

    public function test_an_access_token_is_needed_for_userinfo(): void
    {
        $response = $this->jip->userinfo('unknown-token');

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Bearer error="invalid_token"', $response->headers->get('WWW-Authenticate'));
    }

    /**
     * @param array<string, mixed> $body
     */
    private function assertInvalidClient(int $status, array $body, string $reason): void
    {
        self::assertSame(401, $status);
        self::assertSame('invalid_client', $body['error']);
        self::assertIsString($body['error_description']);
        self::assertStringContainsString($reason, $body['error_description']);
    }
}
