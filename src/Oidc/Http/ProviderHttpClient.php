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
     * @param array<string, string> $headers replace default headers; Accept-Encoding is always identity
     * @param int|null $timeoutSeconds the limit for this request; TIMEOUT_SECONDS when omitted
     * @throws NoAnswer
     */
    public function get(string $url, array $headers = [], ?int $timeoutSeconds = null): ProviderResponse
    {
        return $this->send('GET', $url, ['headers' => $headers + ['Accept' => 'application/json']], $timeoutSeconds);
    }

    /**
     * @param array<string, string> $form
     * @throws NoAnswer
     */
    public function postForm(string $url, array $form): ProviderResponse
    {
        return $this->send('POST', $url, ['body' => $form], null);
    }

    /**
     * @param array{headers?: array<string, string>, body?: array<string, string>} $options
     */
    private function send(string $method, string $url, array $options, ?int $timeoutSeconds): ProviderResponse
    {
        $timeout = $timeoutSeconds ?? self::TIMEOUT_SECONDS;
        // An explicit encoding disables Symfony's automatic decompression. Keep the size limit on
        // the bytes we consume, and reject a provider that sends an encoded body anyway.
        $options['headers'] ??= ['Accept' => 'application/json'];
        foreach (array_keys($options['headers']) as $name) {
            if (strcasecmp($name, 'Accept-Encoding') === 0) {
                unset($options['headers'][$name]);
            }
        }
        $options['headers']['Accept-Encoding'] = 'identity';
        $options += [
            'max_redirects' => 0,
            'timeout' => $timeout,
            'max_duration' => $timeout,
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
            foreach ($response->getHeaders(false)['content-encoding'] ?? [] as $encoding) {
                if (strtolower(trim($encoding)) !== 'identity') {
                    $response->cancel();
                    throw new NoAnswer('The provider answered with an encoded body.');
                }
            }
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
