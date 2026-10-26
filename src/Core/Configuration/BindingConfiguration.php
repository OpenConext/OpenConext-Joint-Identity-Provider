<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

/**
 * The account binding (design §4). It is on for every service; there is no setting that turns it off.
 */
final readonly class BindingConfiguration
{
    public function __construct(
        public string $organisationAttribute,
        public string $claim,
    ) {
    }
}
