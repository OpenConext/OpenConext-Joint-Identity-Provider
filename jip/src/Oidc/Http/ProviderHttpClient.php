<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Http;

use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Every request to the provider: TLS 1.3, no redirects, a time limit and a size limit (design §10, §14).
 * A redirect is never followed, also not to another approved address.
 */
final readonly class ProviderHttpClient
{
    public const int TIMEOUT_SECONDS = 5;
    public const int MAX_BODY_BYTES = 1_048_576;

    public function __construct(private HttpClientInterface $httpClient)
    {
    }

    /**
     * @throws NoAnswer
     */
    public function get(string $url): ProviderResponse
    {
        return $this->send('GET', $url, []);
    }

    /**
     * @param array<string, string> $form
     * @throws NoAnswer
     */
    public function postForm(string $url, array $form): ProviderResponse
    {
        return $this->send('POST', $url, ['body' => $form]);
    }

    /**
     * @param array<string, mixed> $options
     */
    private function send(string $method, string $url, array $options): ProviderResponse
    {
        $options += [
            'headers' => ['Accept' => 'application/json'],
            'max_redirects' => 0,
            'timeout' => self::TIMEOUT_SECONDS,
            'max_duration' => self::TIMEOUT_SECONDS,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
            'on_progress' => static function (int $downloaded, int $expected): void {
                if ($downloaded > self::MAX_BODY_BYTES || $expected > self::MAX_BODY_BYTES) {
                    throw new NoAnswer('The answer is larger than the size limit.');
                }
            },
        ];

        try {
            $response = $this->httpClient->request($method, $url, $options);
            $status = $response->getStatusCode();
            $body = $response->getContent(false);
        } catch (ExceptionInterface $exception) {
            throw new NoAnswer('The request got no answer.', 0, $exception);
        }

        if ($status >= 300 && $status < 400) {
            throw new NoAnswer('The provider answered with a redirect.');
        }
        if ($status >= 500 || $status < 200) {
            throw new NoAnswer('The provider answered with a server error.');
        }
        if (strlen($body) > self::MAX_BODY_BYTES) {
            throw new NoAnswer('The answer is larger than the size limit.');
        }

        return new ProviderResponse($status, $body);
    }
}
