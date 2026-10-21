<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Support;

use JointIdentityProvider\Core\Configuration\ProviderConfiguration;
use JointIdentityProvider\Core\Configuration\Reader\ConfigNode;
use JointIdentityProvider\Core\Profile\ProfileConfiguration;
use JointIdentityProvider\Core\Profile\ProfileOutcome;
use JointIdentityProvider\Core\Profile\ProviderProfile;
use JointIdentityProvider\Core\Transaction\StoredProfileResult;
use JointIdentityProvider\Oidc\AuthenticatedLogin;
use JointIdentityProvider\Profile\Dezi\DeziProfile;

/**
 * A profile whose validation always passes; the core must still not mark success on its own.
 */
final readonly class VerifyingProfile implements ProviderProfile
{
    private DeziProfile $dezi;

    public function __construct()
    {
        $this->dezi = new DeziProfile();
    }

    public function name(): string
    {
        return $this->dezi->name();
    }

    public function messageTypes(): array
    {
        return $this->dezi->messageTypes();
    }

    public function claimNames(): array
    {
        return $this->dezi->claimNames();
    }

    public function bindingClaims(): array
    {
        return $this->dezi->bindingClaims();
    }

    public function providerKeys(): array
    {
        return $this->dezi->providerKeys();
    }

    public function parseConfiguration(ConfigNode $provider, ?int $engineBlockCallTimeoutSeconds): ?ProfileConfiguration
    {
        return $this->dezi->parseConfiguration($provider, $engineBlockCallTimeoutSeconds);
    }

    public function validateLogin(AuthenticatedLogin $login, ProviderConfiguration $provider): ProfileOutcome
    {
        return ProfileOutcome::verified(new StoredProfileResult(
            ['dezi_nummer' => ['900000001']],
            $login->attemptStartedAt->modify('+300 seconds'),
            [],
        ));
    }
}
