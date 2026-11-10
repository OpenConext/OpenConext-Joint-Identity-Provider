<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Login;

use DateTimeImmutable;
use JointIdentityProvider\Core\Transaction\ProviderAttempt;

interface AttemptGenerator
{
    public function generate(DateTimeImmutable $startedAt): ProviderAttempt;
}
