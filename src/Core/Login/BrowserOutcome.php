<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Login;

use JointIdentityProvider\Core\Transaction\Transaction;
use SensitiveParameter;

/**
 * A browser-flow decision, independent of HTTP responses and cookie objects.
 */
final readonly class BrowserOutcome
{
    private function __construct(
        public BrowserOutcomeType $type,
        public ?Transaction $transaction = null,
        public ?string $url = null,
        public ?string $failureType = null,
        public bool $restartable = false,
        public ?string $restartLoginUrl = null,
        public int $status = 200,
        public ?Transaction $cookieTransaction = null,
        #[SensitiveParameter] public ?string $cookieValue = null,
        public bool $clearCookie = false,
    ) {
    }

    public static function unknown(): self
    {
        return new self(BrowserOutcomeType::Unknown, status: 400);
    }

    public static function inProgress(Transaction $transaction): self
    {
        return new self(BrowserOutcomeType::InProgress, $transaction);
    }

    public static function failure(
        string $failureType,
        bool $restartable,
        ?Transaction $transaction,
        ?string $restartLoginUrl,
        int $status = 403,
    ): self {
        return new self(
            BrowserOutcomeType::Failure,
            $transaction,
            failureType: $failureType,
            restartable: $restartable,
            restartLoginUrl: $restartLoginUrl,
            status: $status,
        );
    }

    public static function redirect(
        string $url,
        Transaction $transaction,
        #[SensitiveParameter] ?string $cookieValue = null,
    ): self {
        return new self(
            BrowserOutcomeType::Redirect,
            $transaction,
            $url,
            status: 302,
            cookieTransaction: $cookieValue === null ? null : $transaction,
            cookieValue: $cookieValue,
        );
    }

    public function withClearedCookie(Transaction $transaction): self
    {
        return new self(
            $this->type,
            $this->transaction,
            $this->url,
            $this->failureType,
            $this->restartable,
            $this->restartLoginUrl,
            $this->status,
            $transaction,
            clearCookie: true,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['type' => $this->type, 'status' => $this->status];
    }
}
