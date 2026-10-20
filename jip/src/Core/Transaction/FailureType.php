<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Transaction;

/**
 * Failure types the core records (design §13, §20). All three are final: a new attempt gives the same result.
 */
enum FailureType: string
{
    case OrganisationRefused = 'organisation_refused';
    case ReservedAttribute = 'reserved_attribute';
    case MalformedBinding = 'malformed_binding';
}
