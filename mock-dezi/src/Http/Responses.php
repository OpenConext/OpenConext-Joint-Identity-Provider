<?php

declare(strict_types=1);

namespace MockDezi\Http;

use MockDezi\Message\Jose;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

final class Responses
{
    /**
     * @param array<mixed> $body
     */
    public static function json(
        array $body,
        int $status = Response::HTTP_OK,
        string $contentType = 'application/json',
    ): Response {
        $response = new Response(Jose::json($body), $status, ['Content-Type' => $contentType]);

        return self::noStore($response);
    }

    public static function oauthError(
        string $error,
        string $description,
        int $status = Response::HTTP_BAD_REQUEST,
    ): Response {
        $response = self::json(['error' => $error, 'error_description' => $description], $status);
        if ($status === Response::HTTP_UNAUTHORIZED) {
            $response->headers->set('WWW-Authenticate', sprintf('Bearer error="%s"', $error));
        }

        return $response;
    }

    public static function problem(int $status, string $title): Response
    {
        return self::json(
            ['type' => 'about:blank', 'title' => $title, 'status' => $status],
            $status,
            'application/problem+json',
        );
    }

    /**
     * @param array<string, string> $parameters
     */
    public static function redirectTo(string $url, array $parameters, int $status = Response::HTTP_FOUND): Response
    {
        $separator = str_contains($url, '?') ? '&' : '?';

        return self::noStore(new RedirectResponse(
            $url . $separator . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986),
            $status,
        ));
    }

    public static function noStore(Response $response): Response
    {
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }

    public static function jsonResponse(mixed $data, int $status = Response::HTTP_OK): JsonResponse
    {
        $response = new JsonResponse($data, $status);
        $response->setEncodingOptions(JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
