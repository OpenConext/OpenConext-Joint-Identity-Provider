<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Browser;

use JointIdentityProvider\Core\Login\BrowserOutcome;
use JointIdentityProvider\Core\Login\BrowserOutcomeType;
use LogicException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Turns application outcomes into pages, redirects and transaction cookie headers.
 */
final readonly class BrowserResponder
{
    public function respond(BrowserOutcome $outcome): Response
    {
        $response = match ($outcome->type) {
            BrowserOutcomeType::Unknown => BrowserPages::unknown(),
            BrowserOutcomeType::InProgress => BrowserPages::inProgress(
                $outcome->transaction ?? throw new LogicException('A progress outcome needs a transaction.'),
            ),
            BrowserOutcomeType::Failure => BrowserPages::failure(
                $outcome->failureType ?? throw new LogicException('A failure outcome needs a failure type.'),
                $outcome->restartable,
                $outcome->transaction,
                $outcome->restartLoginUrl,
                $outcome->status,
            ),
            BrowserOutcomeType::Redirect => BrowserPages::redirect(
                $outcome->url ?? throw new LogicException('A redirect outcome needs a URL.'),
            ),
        };

        if ($outcome->cookieTransaction !== null) {
            if ($outcome->clearCookie) {
                $response->headers->setCookie(TransactionCookie::clear($outcome->cookieTransaction));
            } elseif ($outcome->cookieValue !== null) {
                $response->headers->setCookie(TransactionCookie::create(
                    $outcome->cookieTransaction,
                    $outcome->cookieValue,
                ));
            }
        }

        return $response;
    }
}
