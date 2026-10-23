<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Oidc;

use JointIdentityProvider\Oidc\Http\NoAnswer;
use JointIdentityProvider\Oidc\Http\ProviderHttpClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class ProviderHttpClientTest extends TestCase
{
    public function test_the_request_honours_a_timeout_above_five_seconds(): void
    {
        $client = new MockHttpClient(static function (string $method, string $url, array $options): MockResponse {
            self::assertSame(10.0, $options['timeout']);
            self::assertSame(10.0, $options['max_duration']);
            self::assertIsArray($options['normalized_headers']);
            self::assertSame(['Accept-Encoding: identity'], $options['normalized_headers']['accept-encoding']);

            return new MockResponse('{}');
        });

        self::assertSame('{}', (new ProviderHttpClient($client))->get('https://provider.example/status', [], 10)->body);
    }

    public function test_an_unsolicited_gzip_bomb_is_refused(): void
    {
        // MockResponse does not decompress. The explicit identity header disables decompression in
        // the real transport; an encoded answer must still be refused, even below the wire limit.
        $body = gzencode(str_repeat('a', 2 * ProviderHttpClient::MAX_BODY_BYTES));
        self::assertIsString($body);
        self::assertLessThan(ProviderHttpClient::MAX_BODY_BYTES, strlen($body));
        $response = new MockResponse($body, ['response_headers' => ['Content-Encoding: gzip']]);
        $client = new MockHttpClient($response);

        try {
            (new ProviderHttpClient($client))->get('https://provider.example/status');
            self::fail('An encoded body was accepted.');
        } catch (NoAnswer $exception) {
            self::assertSame('The provider answered with an encoded body.', $exception->getMessage());
        }
    }

    public function test_form_requests_keep_the_default_timeout_and_json_accept_header(): void
    {
        $client = new MockHttpClient(static function (string $method, string $url, array $options): MockResponse {
            self::assertSame(5.0, $options['timeout']);
            self::assertSame(5.0, $options['max_duration']);
            self::assertIsArray($options['normalized_headers']);
            self::assertSame(['Accept: application/json'], $options['normalized_headers']['accept']);
            self::assertSame(['Accept-Encoding: identity'], $options['normalized_headers']['accept-encoding']);

            return new MockResponse('{}');
        });

        self::assertSame('{}', (new ProviderHttpClient($client))->postForm('https://provider.example/token', [])->body);
    }
}
