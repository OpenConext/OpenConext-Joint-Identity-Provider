<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Profile;

use JointIdentityProvider\Core\Configuration\Reader\ConfigNode;
use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

/**
 * A provider profile reads one provider's messages on top of the standard OIDC client (design §2).
 * The core asks the profile for everything provider-specific; it holds no provider names itself.
 */
#[AutoconfigureTag(self::TAG)]
interface ProviderProfile
{
    public const string TAG = 'jip.provider_profile';

    /**
     * The value of `provider.profile` that selects this profile.
     */
    public function name(): string;

    /**
     * Message types, next to the OIDC client's `id_token`, that need their own approved key address
     * and expected issuer.
     *
     * @return list<string>
     */
    public function messageTypes(): array;

    /**
     * Claim names this profile can put in a verified claim set.
     *
     * @return list<string>
     */
    public function claimNames(): array;

    /**
     * Claim names this profile allows as `binding.claim`.
     *
     * @return list<string>
     */
    public function bindingClaims(): array;

    /**
     * Keys of the `provider` block that this profile owns.
     *
     * @return list<string>
     */
    public function providerKeys(): array;

    /**
     * Validates the profile's own keys of the `provider` block. Reports every problem on the node and
     * returns null when one was found.
     */
    public function parseConfiguration(
        ConfigNode $provider,
        ?int $engineBlockCallTimeoutSeconds,
    ): ?ProfileConfiguration;
}
