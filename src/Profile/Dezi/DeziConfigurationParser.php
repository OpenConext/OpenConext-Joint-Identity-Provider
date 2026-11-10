<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

use JointIdentityProvider\Configuration\Reader\ConfigNode;

/**
 * Validates the DEZI-owned provider settings, including client audiences and revocation timing.
 */
final readonly class DeziConfigurationParser
{
    public const array PROVIDER_KEYS = ['expected_assurance', 'revocation', 'envelope', 'statement'];

    // The envelope's own claims; the statement claim cannot be one of them.
    private const array ENVELOPE_CLAIMS = ['iss', 'aud', 'sub', 'iat', 'nbf', 'exp', 'loa_authn', 'verklaring_id'];

    public function parse(
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
}
