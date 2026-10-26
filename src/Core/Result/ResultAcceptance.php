<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Result;

use DateTimeImmutable;
use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Core\Profile\ProfileResult;
use JointIdentityProvider\Core\Transaction\FailureType;
use JointIdentityProvider\Core\Transaction\StoredProfileResult;
use JointIdentityProvider\Core\Transaction\Transaction;

/**
 * The core's own checks on a verified profile result before a transaction succeeds (design §4, §14, §17):
 * the required claims of the claim mapping, then the account binding as an exact string comparison of
 * `binding.claim` with the organisation's number. Only the claims the service releases are kept.
 */
final class ResultAcceptance
{
    public static function accept(
        Transaction $validating,
        ProfileResult $result,
        JipConfiguration $configuration,
        DateTimeImmutable $now,
    ): Transaction|FailureType {
        $service = $configuration->services[$validating->serviceId] ?? null;
        if ($service === null) {
            return FailureType::ServiceNotConfigured;
        }

        $claims = $result->verifiedClaims();
        foreach ($configuration->attributes->claims as $name => $mapping) {
            if ($mapping->required && ($claims[$name] ?? []) === []) {
                return FailureType::RequiredClaimMissing;
            }
        }

        $organisationValue = $validating->organisationBindingValue;
        if ($organisationValue === '' || ($claims[$configuration->binding->claim] ?? null) !== [$organisationValue]) {
            return FailureType::BindingMismatch;
        }

        $released = array_intersect_key($claims, array_flip($service->release));
        if ($released === []) {
            return FailureType::NothingToRelease;
        }

        if ($result->hardExpiry() <= $now) {
            return FailureType::Expired;
        }

        return $validating->succeeded(
            new StoredProfileResult($released, $result->hardExpiry(), $result->recheckState()),
            $result->hardExpiry(),
        );
    }
}
