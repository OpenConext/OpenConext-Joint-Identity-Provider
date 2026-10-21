<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Transaction;

/**
 * Failure types the core records or shows (design §13, §20). The OIDC client and the profile add their own.
 */
enum FailureType: string
{
    case InternalError = 'internal_error';
    case OrganisationRefused = 'organisation_refused';
    case ReservedAttribute = 'reserved_attribute';
    case MalformedBinding = 'malformed_binding';
    case Expired = 'expired';
    case AlreadyUsed = 'already_used';
    case CallbackMismatch = 'callback_mismatch';
    case ServiceNotConfigured = 'service_not_configured';
    case InvalidReturnUrl = 'invalid_return_url';
    case ResultCompletionUnavailable = 'result_completion_unavailable';

    public function isRestartable(): bool
    {
        return in_array($this, [self::Expired, self::AlreadyUsed, self::CallbackMismatch], true);
    }
}
