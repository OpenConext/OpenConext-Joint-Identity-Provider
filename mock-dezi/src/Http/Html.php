<?php

declare(strict_types=1);

namespace MockDezi\Http;

use Symfony\Component\HttpFoundation\Response;

/**
 * Minimal HTML pages for the simulated DEZI login. Every dynamic value goes through e().
 */
final class Html
{
    public static function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }

    public static function page(string $title, string $body, int $status = Response::HTTP_OK): Response
    {
        $html = <<<HTML
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <title>{$title} - mock DEZI provider</title>
            <style>
            body { font-family: sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; }
            .banner { background: #fde68a; border: 1px solid #b45309; padding: .5rem 1rem; }
            table { border-collapse: collapse; }
            td, th { border: 1px solid #ccc; padding: .25rem .5rem; text-align: left; }
            fieldset { margin: 1rem 0; } label { display: block; margin: .25rem 0; }
            </style>
            </head>
            <body>
            <p class="banner"><strong>Mock DEZI provider.</strong> Synthetic data for local JIP development only.
            This is not DEZI and no real means of authentication is used.</p>
            <h1>{$title}</h1>
            {$body}
            </body>
            </html>
            HTML;

        $response = new Response($html, $status, ['Content-Type' => 'text/html; charset=utf-8']);
        $response->headers->set(
            'Content-Security-Policy',
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        );
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        return Responses::noStore($response);
    }

    public static function error(string $message, int $status = Response::HTTP_BAD_REQUEST): Response
    {
        return self::page('Error', '<p>' . self::e($message) . '</p>', $status);
    }
}
