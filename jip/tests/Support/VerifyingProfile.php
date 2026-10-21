<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Support;

use DateTimeImmutable;
use JointIdentityProvider\Core\Configuration\ProviderConfiguration;
use JointIdentityProvider\Core\Configuration\Reader\ConfigNode;
use JointIdentityProvider\Core\Profile\ProfileConfiguration;
use JointIdentityProvider\Core\Profile\ProfileOutcome;
use JointIdentityProvider\Core\Profile\ProfileResult;
use JointIdentityProvider\Core\Profile\ProviderProfile;
use JointIdentityProvider\Core\Profile\RecheckResult;
use JointIdentityProvider\Core\Transaction\StoredProfileResult;
use JointIdentityProvider\Oidc\AuthenticatedLogin;
use JointIdentityProvider\Profile\Dezi\DeziProfile;
use JointIdentityProvider\Tests\Support\ConfigurationFixture as Fixture;

/**
 * A profile whose validation passes with the given claims, so tests reach the core's own checks.
 */
final readonly class VerifyingProfile implements ProviderProfile
{
    private DeziProfile $dezi;

    /**
     * @param array<string, list<string>> $claims
     */
    public function __construct(
        private array $claims = ['dezi_nummer' => ['900000001'], 'abonnee_nummer' => ['90000001']],
    ) {
        $this->dezi = Fixture::deziProfile();
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
            $this->claims,
            $login->attemptStartedAt->modify('+300 seconds'),
            [],
        ));
    }

    public function recheck(ProfileResult $result, ProviderConfiguration $provider, DateTimeImmutable $now): RecheckResult
    {
        return RecheckResult::passed($result, $result, $result->hardExpiry());
    }
}
