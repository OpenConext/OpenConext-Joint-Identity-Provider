<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Browser;

use JointIdentityProvider\Core\Transaction\Transaction;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * The browser answers of `/interrupt` and `/oidc/callback` (design §13). Error pages show the log ID and
 * link to the service's approved restart-login URL only for a failure that a new attempt can fix.
 */
final class BrowserPages
{
    public static function redirect(string $url): RedirectResponse
    {
        return self::secure(new RedirectResponse($url, Response::HTTP_FOUND));
    }

    public static function inProgress(Transaction $transaction): Response
    {
        return self::page(
            Response::HTTP_OK,
            'Login in progress',
            'This login is already in progress in another window or tab. Continue there.',
            $transaction->logId,
            null,
        );
    }

    /**
     * No transaction belongs to the request, so no service, log ID or restart URL is known.
     */
    public static function unknown(): Response
    {
        return self::page(
            Response::HTTP_BAD_REQUEST,
            'Login link not valid',
            'This login link is not valid or has expired. Start the login again from the application.',
            null,
            null,
        );
    }

    public static function failure(
        string $failureType,
        bool $restartable,
        ?Transaction $transaction,
        ?string $restartLoginUrl,
        int $status = Response::HTTP_FORBIDDEN,
    ): Response {
        return self::page(
            $status,
            'Login could not be completed',
            $restartable
                ? 'The login could not be completed. You can start the login again.'
                : 'The login could not be completed. Contact support and quote the log ID below.',
            $transaction?->logId,
            $restartable ? $restartLoginUrl : null,
            $failureType,
        );
    }

    private static function page(
        int $status,
        string $title,
        string $message,
        ?string $logId,
        ?string $restartLoginUrl,
        ?string $failureType = null,
    ): Response {
        $html = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>JIP: ' . self::e($title)
            . '</title></head><body><header><p><strong>JointIdentityProvider (JIP)</strong></p></header><h1>'
            . self::e($title) . '</h1><p>' . self::e($message) . '</p>';
        if ($failureType !== null) {
            $html .= '<p>Reason: <code>' . self::e($failureType) . '</code></p>';
        }
        if ($logId !== null) {
            $html .= '<p>Log ID: <code>' . self::e($logId) . '</code></p>';
        }
        if ($restartLoginUrl !== null) {
            $html .= '<p><a href="' . self::e($restartLoginUrl) . '">Restart login</a></p>';
        }
        $html .= '</body></html>';

        $response = new Response($html, $status, ['Content-Type' => 'text/html; charset=UTF-8']);
        $response->headers->set(
            'Content-Security-Policy',
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        );

        return self::secure($response);
    }

    /**
     * @template T of Response
     * @param T $response
     * @return T
     */
    private static function secure(Response $response): Response
    {
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set('X-Frame-Options', 'DENY');

        return $response;
    }

    private static function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
