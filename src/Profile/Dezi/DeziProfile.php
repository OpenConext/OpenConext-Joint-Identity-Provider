<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

use DateTimeImmutable;
use JointIdentityProvider\Configuration\Reader\ConfigNode;
use JointIdentityProvider\Core\Configuration\ProviderConfiguration;
use JointIdentityProvider\Core\Profile\ProfileOutcome;
use JointIdentityProvider\Core\Profile\ProfileResult;
use JointIdentityProvider\Core\Profile\ProviderProfile;
use JointIdentityProvider\Core\Profile\RecheckResult;
use JointIdentityProvider\Core\Transaction\StoredProfileResult;
use JointIdentityProvider\Oidc\AuthenticatedLogin;
use JointIdentityProvider\Oidc\OidcFailure;
use LogicException;
use Psr\Clock\ClockInterface;

/**
 * The DEZI profile (design §2, §14–§16). It holds the DEZI-specific names; the core gets them from here
 * and from the claim mapping in the configuration. It hands the core the verified claim set, the hard
 * expiry of the proof (envelope and statement) and a delivery-time recheck of the revocation decision.
 */
final readonly class DeziProfile implements ProviderProfile
{
    public const string NAME = 'dezi';

    // The profile's result data kept with the transaction (design §13).
    public const string STATE_VERKLARING_ID = 'verklaring_id';
    public const string STATE_DECISION_VALID_UNTIL = 'decision_valid_until_us';

    public function __construct(
        private UserInfoReader $userInfo,
        private ProofValidator $proofs,
        private RevocationChecker $revocation,
        private ClockInterface $clock,
        private DeziConfigurationParser $parser,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function messageTypes(): array
    {
        // The revocation list is a message type only with status_check_with_list, which is not supported.
        return [ProofValidator::ENVELOPE, ProofValidator::STATEMENT];
    }

    public function claimNames(): array
    {
        return ProofValidator::RELEASABLE_CLAIMS;
    }

    public function bindingClaims(): array
    {
        return ['dezi_nummer'];
    }

    public function providerKeys(): array
    {
        return DeziConfigurationParser::PROVIDER_KEYS;
    }

    public function parseConfiguration(
        ConfigNode $provider,
        ?int $engineBlockCallTimeoutSeconds,
    ): ?DeziProfileConfiguration {
        return $this->parser->parse($provider, $engineBlockCallTimeoutSeconds);
    }

    public function validateLogin(AuthenticatedLogin $login, ProviderConfiguration $provider): ProfileOutcome
    {
        $configuration = self::configuration($provider);

        try {
            $envelope = $this->userInfo->read($login);
            $proof = $this->proofs->validate($envelope, $login, $provider, $configuration, $this->clock->now());
            $decisionValidUntil = $this->revocation->check($proof->verklaringId, $configuration->revocation);
        } catch (DeziFailure $failure) {
            return ProfileOutcome::failed($failure->type->value, $failure->type->isRestartable(), $failure->detail);
        } catch (OidcFailure $failure) {
            // No usable key for the envelope or the statement.
            return ProfileOutcome::failed($failure->type->value, $failure->type->isRestartable(), $failure->detail);
        }

        return ProfileOutcome::verified(
            self::result($proof->claims, $proof->hardExpiry, $proof->verklaringId, $decisionValidUntil),
        );
    }

    /**
     * Renews a revocation decision whose validity has been reached, or ends within the status check's
     * timeout, with one status check (design §15). Renewal never extends the hard expiry.
     */
    public function recheck(
        ProfileResult $result,
        ProviderConfiguration $provider,
        DateTimeImmutable $now,
    ): RecheckResult {
        $configuration = self::configuration($provider);
        $state = $result->recheckState();
        $verklaringId = $state[self::STATE_VERKLARING_ID] ?? null;
        $validUntilMicros = $state[self::STATE_DECISION_VALID_UNTIL] ?? null;
        if (!is_string($verklaringId) || !is_int($validUntilMicros)) {
            throw new LogicException('The stored result has no revocation decision.');
        }

        $validUntil = self::fromMicros($validUntilMicros);
        // A decision that would end before the consuming write is renewed now, not refused there.
        $margin = sprintf('-%d seconds', $configuration->revocation->timeoutSeconds);
        if ($now < $validUntil->modify($margin)) {
            return RecheckResult::passed($result, $result, $validUntil);
        }

        try {
            $renewedUntil = $this->revocation->check($verklaringId, $configuration->revocation);
        } catch (DeziFailure $failure) {
            return RecheckResult::failed($failure->type->value, $failure->type->isRestartable());
        }

        return RecheckResult::passed(
            $result,
            self::result($result->verifiedClaims(), $result->hardExpiry(), $verklaringId, $renewedUntil),
            $renewedUntil,
        );
    }

    private static function configuration(ProviderConfiguration $provider): DeziProfileConfiguration
    {
        $configuration = $provider->profileConfiguration;
        if (!$configuration instanceof DeziProfileConfiguration) {
            throw new LogicException('The provider is not configured for the DEZI profile.');
        }

        return $configuration;
    }

    /**
     * @param array<string, list<string>> $claims
     */
    private static function result(
        array $claims,
        DateTimeImmutable $hardExpiry,
        string $verklaringId,
        DateTimeImmutable $decisionValidUntil,
    ): StoredProfileResult {
        return new StoredProfileResult($claims, $hardExpiry, [
            self::STATE_VERKLARING_ID => $verklaringId,
            self::STATE_DECISION_VALID_UNTIL => (int) $decisionValidUntil->format('Uu'),
        ]);
    }

    private static function fromMicros(int $micros): DateTimeImmutable
    {
        $time = DateTimeImmutable::createFromFormat(
            'U.u',
            sprintf('%d.%06d', intdiv($micros, 1_000_000), $micros % 1_000_000),
        );

        return $time !== false ? $time : throw new LogicException('The stored decision time is not valid.');
    }
}
