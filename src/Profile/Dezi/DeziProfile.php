<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

use DateTimeImmutable;
use JointIdentityProvider\Core\Configuration\ProviderConfiguration;
use JointIdentityProvider\Core\Configuration\Reader\ConfigNode;
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

    // The envelope's own claims; the statement claim cannot be one of them.
    private const array ENVELOPE_CLAIMS = ['iss', 'aud', 'sub', 'iat', 'nbf', 'exp', 'loa_authn', 'verklaring_id'];

    public function __construct(
        private UserInfoReader $userInfo,
        private ProofValidator $proofs,
        private RevocationChecker $revocation,
        private ClockInterface $clock,
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
        return ['expected_assurance', 'revocation', 'envelope', 'statement'];
    }

    public function parseConfiguration(
        ConfigNode $provider,
        ?int $engineBlockCallTimeoutSeconds,
    ): ?DeziProfileConfiguration {
        $assurance = $provider->get('expected_assurance');
        $loaAuthn = null;
        $loaDezi = null;
        if ($assurance->requireMap()) {
            $assurance->allowOnly('loa_authn', 'loa_dezi');
            $loaAuthn = $assurance->get('loa_authn')->requireString();
            $loaDezi = $assurance->get('loa_dezi')->requireString();
        }

        $revocation = $this->parseRevocation($provider->get('revocation'), $engineBlockCallTimeoutSeconds);
        $envelope = $this->parseEnvelope($provider->get('envelope'), array_keys($provider->get('clients')->entries()));
        $nullableClaims = $this->parseStatement($provider->get('statement'));

        if (
            $loaAuthn === null || $loaDezi === null || $revocation === null || $envelope === null
            || $nullableClaims === null
        ) {
            return null;
        }

        return new DeziProfileConfiguration(
            $loaAuthn,
            $loaDezi,
            $revocation,
            $envelope[0],
            $envelope[1],
            $envelope[2],
            $nullableClaims,
        );
    }

    /**
     * @param list<string> $clientNames names declared under provider.clients
     * @return array{string, SubjectAssociation, array<string, string>}|null
     */
    private function parseEnvelope(ConfigNode $node, array $clientNames): ?array
    {
        if (!$node->requireMap()) {
            return null;
        }
        $node->allowOnly('statement_claim', 'subject_association', 'audiences');

        $statementClaimNode = $node->get('statement_claim');
        $statementClaim = $statementClaimNode->requireString();
        if ($statementClaim !== null && in_array($statementClaim, self::ENVELOPE_CLAIMS, true)) {
            $statementClaimNode->error('must not be one of the envelope\'s own claims');
            $statementClaim = null;
        }

        $associationNode = $node->get('subject_association');
        $associationValue = $associationNode->requireString();
        $association = $associationValue === null ? null : SubjectAssociation::tryFrom($associationValue);
        if ($associationValue !== null && $association === null) {
            $associationNode->error('must be envelope_sub or access_token');
        }

        $audiences = $this->parseAudiences($node->get('audiences'), $clientNames);

        if ($statementClaim === null || $association === null || $audiences === null) {
            return null;
        }

        return [$statementClaim, $association, $audiences];
    }

    /**
     * One envelope audience per client under provider.clients, as confirmed for its registration.
     *
     * @param list<string> $clientNames
     * @return array<string, string>|null
     */
    private function parseAudiences(ConfigNode $node, array $clientNames): ?array
    {
        if (!$node->requireMap()) {
            return null;
        }

        $valid = true;
        foreach ($node->entries() as $name => $entry) {
            if (!in_array($name, $clientNames, true)) {
                $entry->error('is not a client under provider.clients');
                $valid = false;
            }
        }

        $audiences = [];
        foreach ($clientNames as $name) {
            $audience = $node->get($name)->requireString();
            if ($audience === null) {
                $valid = false;
            } else {
                $audiences[$name] = $audience;
            }
        }

        return $valid ? $audiences : null;
    }

    /**
     * @return list<string>|null
     */
    private function parseStatement(ConfigNode $node): ?array
    {
        if (!$node->requireMap()) {
            return null;
        }
        $node->allowOnly('nullable_claims');

        $listNode = $node->get('nullable_claims');
        $claims = $listNode->requireUniqueStringList();
        if ($claims === null) {
            return null;
        }

        $valid = true;
        foreach ($claims as $index => $claim) {
            if (
                !in_array($claim, ProofValidator::RELEASABLE_CLAIMS, true)
                || in_array($claim, ProofValidator::REQUIRED_CLAIMS, true)
            ) {
                $listNode->get($index)->error('must name an optional statement claim');
                $valid = false;
            }
        }

        return $valid ? $claims : null;
    }

    private function parseRevocation(
        ConfigNode $node,
        ?int $engineBlockCallTimeoutSeconds,
    ): ?DeziRevocationConfiguration {
        if (!$node->requireMap()) {
            return null;
        }
        $node->allowOnly('mode', 'status_address', 'list_address', 'timeout_seconds', 'decision_validity_seconds');

        $modeNode = $node->get('mode');
        $mode = $modeNode->requireString();
        if ($mode === DeziRevocationConfiguration::MODE_STATUS_CHECK_WITH_LIST) {
            $modeNode->error('status_check_with_list is not supported; this version uses status_check only');
            $mode = null;
        } elseif ($mode !== null && $mode !== DeziRevocationConfiguration::MODE_STATUS_CHECK) {
            $modeNode->error('must be status_check');
            $mode = null;
        }

        if ($node->get('list_address')->isPresent()) {
            $node->get('list_address')->error('is only used with status_check_with_list, which is not supported');
        }

        $statusAddressNode = $node->get('status_address');
        $statusAddress = $statusAddressNode->requireHttpsUrl();
        if (
            $statusAddress !== null
            && substr_count($statusAddress, DeziRevocationConfiguration::STATUS_ADDRESS_PLACEHOLDER) !== 1
        ) {
            $statusAddressNode->error(sprintf(
                'must contain %s exactly once',
                DeziRevocationConfiguration::STATUS_ADDRESS_PLACEHOLDER,
            ));
            $statusAddress = null;
        }

        $timeoutNode = $node->get('timeout_seconds');
        $timeout = $timeoutNode->requirePositiveInt();
        if (
            $timeout !== null && $engineBlockCallTimeoutSeconds !== null
            && 2 * $timeout > $engineBlockCallTimeoutSeconds
        ) {
            $timeoutNode->error('must not be more than half of engineblock.call_timeout_seconds');
            $timeout = null;
        }

        $decisionValidity = $node->get('decision_validity_seconds')->requirePositiveInt();

        if (
            $mode === null || $statusAddress === null || $timeout === null || $decisionValidity === null
            || $node->get('list_address')->isPresent()
        ) {
            return null;
        }

        return new DeziRevocationConfiguration($mode, $statusAddress, $timeout, $decisionValidity);
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
