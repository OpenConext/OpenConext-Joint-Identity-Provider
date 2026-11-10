<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Login;

use DateTimeImmutable;
use JointIdentityProvider\Core\Transaction\ProviderAttempt;
use JointIdentityProvider\Oidc\Jose\Base64Url;
use JointIdentityProvider\Oidc\Pkce;

final readonly class RandomAttemptGenerator implements AttemptGenerator
{
    public function generate(DateTimeImmutable $startedAt): ProviderAttempt
    {
        return new ProviderAttempt(
            Base64Url::randomToken(),
            Base64Url::randomToken(),
            Pkce::verifier(),
            Base64Url::randomToken(),
            $startedAt,
        );
    }
}
