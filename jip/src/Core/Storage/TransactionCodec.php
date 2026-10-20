<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Storage;

use DateTimeImmutable;
use JointIdentityProvider\Core\Transaction\ProviderAttempt;
use JointIdentityProvider\Core\Transaction\StoredProfileResult;
use JointIdentityProvider\Core\Transaction\Transaction;
use JointIdentityProvider\Core\Transaction\TransactionState;
use UnexpectedValueException;

/**
 * Converts a transaction to and from the JSON the store keeps. Times are integer microseconds since the epoch.
 */
final class TransactionCodec
{
    public static function encode(Transaction $transaction): string
    {
        $attempt = $transaction->attempt;
        $result = $transaction->profileResult;

        return json_encode([
            'id' => $transaction->id,
            'logId' => $transaction->logId,
            'serviceId' => $transaction->serviceId,
            'organisationId' => $transaction->organisationId,
            'userId' => $transaction->userId,
            'connectionPolicyVersionAtStart' => $transaction->connectionPolicyVersionAtStart,
            'organisationBindingValue' => $transaction->organisationBindingValue,
            'returnUrl' => $transaction->returnUrl,
            'transactionDeadline' => self::micros($transaction->transactionDeadline),
            'state' => $transaction->state->value,
            'attempt' => $attempt === null ? null : [
                'oidcState' => $attempt->oidcState,
                'oidcNonce' => $attempt->oidcNonce,
                'pkceVerifier' => $attempt->pkceVerifier,
                'cookieValue' => $attempt->cookieValue,
                'startedAt' => self::micros($attempt->startedAt),
            ],
            'profileResult' => $result === null ? null : [
                'verifiedClaims' => (object) $result->verifiedClaims(),
                'hardExpiry' => self::micros($result->hardExpiry()),
                'recheckState' => (object) $result->recheckState(),
            ],
            'resultDeadline' => $transaction->resultDeadline === null
                ? null
                : self::micros($transaction->resultDeadline),
            'failureType' => $transaction->failureType,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * @throws UnexpectedValueException when the stored record is not a transaction
     */
    public static function decode(string $json): Transaction
    {
        $data = self::map(json_decode($json, true, 16, JSON_THROW_ON_ERROR), 'record');
        $state = TransactionState::tryFrom(self::string($data, 'state'))
            ?? throw new UnexpectedValueException('The stored transaction has an unknown state.');

        return new Transaction(
            self::string($data, 'id'),
            self::string($data, 'logId'),
            self::string($data, 'serviceId'),
            self::string($data, 'organisationId'),
            self::string($data, 'userId'),
            self::string($data, 'connectionPolicyVersionAtStart'),
            self::string($data, 'organisationBindingValue'),
            self::string($data, 'returnUrl'),
            self::time($data, 'transactionDeadline'),
            $state,
            self::attempt($data['attempt'] ?? null),
            self::profileResult($data['profileResult'] ?? null),
            ($data['resultDeadline'] ?? null) === null ? null : self::time($data, 'resultDeadline'),
            ($data['failureType'] ?? null) === null ? null : self::string($data, 'failureType'),
        );
    }

    public static function micros(DateTimeImmutable $time): int
    {
        return (int) $time->format('Uu');
    }

    private static function attempt(mixed $value): ?ProviderAttempt
    {
        if ($value === null) {
            return null;
        }
        $data = self::map($value, 'attempt');

        return new ProviderAttempt(
            self::string($data, 'oidcState'),
            self::string($data, 'oidcNonce'),
            self::string($data, 'pkceVerifier'),
            self::string($data, 'cookieValue'),
            self::time($data, 'startedAt'),
        );
    }

    private static function profileResult(mixed $value): ?StoredProfileResult
    {
        if ($value === null) {
            return null;
        }
        $data = self::map($value, 'profileResult');

        $claims = [];
        foreach (self::map($data['verifiedClaims'] ?? null, 'verifiedClaims') as $claim => $values) {
            if (!is_array($values) || !array_is_list($values)) {
                throw new UnexpectedValueException('A stored claim does not hold a list of values.');
            }
            $claims[$claim] = array_map(
                static fn (mixed $item): string => is_string($item)
                    ? $item
                    : throw new UnexpectedValueException('A stored claim value is not a string.'),
                $values,
            );
        }

        $recheckState = [];
        foreach (self::map($data['recheckState'] ?? null, 'recheckState') as $key => $item) {
            if (!is_string($item) && !is_int($item) && $item !== null) {
                throw new UnexpectedValueException('A stored recheck value has an unsupported type.');
            }
            $recheckState[$key] = $item;
        }

        return new StoredProfileResult($claims, self::time($data, 'hardExpiry'), $recheckState);
    }

    /**
     * @return array<string, mixed>
     */
    private static function map(mixed $value, string $name): array
    {
        if (!is_array($value)) {
            throw new UnexpectedValueException(sprintf('The stored %s is not a map.', $name));
        }

        $map = [];
        foreach ($value as $key => $item) {
            if (!is_string($key)) {
                throw new UnexpectedValueException(sprintf('The stored %s has a key that is not a string.', $name));
            }
            $map[$key] = $item;
        }

        return $map;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        return is_string($value)
            ? $value
            : throw new UnexpectedValueException(sprintf('The stored field %s is not a string.', $key));
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function time(array $data, string $key): DateTimeImmutable
    {
        $value = $data[$key] ?? null;
        if (!is_int($value) || $value < 0) {
            throw new UnexpectedValueException(sprintf('The stored time %s is not valid.', $key));
        }

        $time = DateTimeImmutable::createFromFormat(
            'U.u',
            sprintf('%d.%06d', intdiv($value, 1_000_000), $value % 1_000_000),
        );

        return $time !== false
            ? $time
            : throw new UnexpectedValueException(sprintf('The stored time %s is not valid.', $key));
    }
}
