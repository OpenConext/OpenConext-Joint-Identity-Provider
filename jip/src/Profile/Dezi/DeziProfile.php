<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

use JointIdentityProvider\Core\Configuration\ProviderConfiguration;
use JointIdentityProvider\Core\Configuration\Reader\ConfigNode;
use JointIdentityProvider\Core\Profile\ProfileOutcome;
use JointIdentityProvider\Core\Profile\ProviderProfile;
use JointIdentityProvider\Oidc\AuthenticatedLogin;

/**
 * The DEZI profile (design §2, §14–§16). It holds the DEZI-specific names; the core gets them from here
 * and from the claim mapping in the configuration.
 */
final readonly class DeziProfile implements ProviderProfile
{
    public const string NAME = 'dezi';
    public const string FAILURE_VALIDATION_UNAVAILABLE = 'dezi_validation_unavailable';

    // Statement claims that may be released (design §6). Technical claims such as loa_dezi and
    // verklaring_id are validated by the profile and never released.
    private const array RELEASABLE_CLAIMS = [
        'dezi_nummer',
        'abonnee_nummer',
        'rol_code',
        'rol_naam',
        'abonnee_naam',
        'voorletters',
        'voorvoegsel',
        'achternaam',
    ];

    public function name(): string
    {
        return self::NAME;
    }

    public function messageTypes(): array
    {
        // The revocation list is a message type only with status_check_with_list, which is not supported.
        return ['envelope', 'statement'];
    }

    public function claimNames(): array
    {
        return self::RELEASABLE_CLAIMS;
    }

    public function bindingClaims(): array
    {
        return ['dezi_nummer'];
    }

    public function providerKeys(): array
    {
        return ['expected_assurance', 'revocation'];
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

        if ($loaAuthn === null || $loaDezi === null || $revocation === null) {
            return null;
        }

        return new DeziProfileConfiguration($loaAuthn, $loaDezi, $revocation);
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
        // UserInfo decryption and the envelope, statement and revocation checks (design §14–§16) are not
        // implemented yet, so no DEZI login can pass.
        return ProfileOutcome::failed(
            self::FAILURE_VALIDATION_UNAVAILABLE,
            false,
            'DEZI proof validation is not implemented',
        );
    }
}
