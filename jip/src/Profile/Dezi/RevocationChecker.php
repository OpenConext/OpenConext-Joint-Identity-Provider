<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

use DateTimeImmutable;
use JointIdentityProvider\Oidc\Http\NoAnswer;
use JointIdentityProvider\Oidc\Http\ProviderHttpClient;
use Psr\Clock\ClockInterface;

/**
 * The live status check per statement (design §15). The URL comes from `revocation.status_address` and
 * the statement's `verklaring_id`; a link inside the statement is never called. Only HTTP 200 with the
 * same `verklaringId` and `status` `actief` is active. A 4xx is a definite answer and refuses the result;
 * a timeout, an unreachable address, a 5xx, a redirect or an invalid body is no answer and refuses it too.
 */
final readonly class RevocationChecker
{
    // The field names and active value of design §15; the CIBG has not yet confirmed them (§10, §16).
    public const string ID_FIELD = 'verklaringId';
    public const string STATUS_FIELD = 'status';
    public const string ACTIVE = 'actief';

    public function __construct(
        private ProviderHttpClient $http,
        private ClockInterface $clock,
    ) {
    }

    /**
     * Makes exactly one request. Returns until when the active decision holds, counted from the request.
     *
     * @param string $verklaringId a validated UUID
     * @throws DeziFailure when the statement is not shown to be active
     */
    public function check(string $verklaringId, DeziRevocationConfiguration $configuration): DateTimeImmutable
    {
        $url = str_replace(
            DeziRevocationConfiguration::STATUS_ADDRESS_PLACEHOLDER,
            rawurlencode($verklaringId),
            $configuration->statusAddressTemplate,
        );

        $checkedAt = $this->clock->now();
        try {
            $response = $this->http->get($url, [], $configuration->timeoutSeconds);
        } catch (NoAnswer $exception) {
            throw new DeziFailure(DeziFailureType::StatusCheckUnavailable, 'status check: no answer', $exception);
        }

        if ($response->statusCode === 404) {
            throw new DeziFailure(DeziFailureType::StatementUnknown, 'status check: DEZI does not know the statement');
        }
        if ($response->statusCode >= 400) {
            throw new DeziFailure(DeziFailureType::StatusRequestRefused, 'status check: DEZI rejected the request');
        }
        if ($response->statusCode !== 200) {
            throw new DeziFailure(DeziFailureType::StatusCheckUnavailable, 'status check: answer is not HTTP 200');
        }

        $body = $response->jsonObject();
        if ($body === null) {
            throw new DeziFailure(DeziFailureType::StatusCheckUnavailable, 'status check: invalid body');
        }
        if (($body[self::ID_FIELD] ?? null) !== $verklaringId) {
            throw new DeziFailure(DeziFailureType::StatementNotActive, 'status check: answer is for another statement');
        }
        if (($body[self::STATUS_FIELD] ?? null) !== self::ACTIVE) {
            throw new DeziFailure(DeziFailureType::StatementNotActive, 'status check: statement is not active');
        }

        return $checkedAt->modify(sprintf('+%d seconds', $configuration->decisionValiditySeconds));
    }
}
