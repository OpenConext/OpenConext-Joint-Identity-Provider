<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

/**
 * Failure types of the DEZI profile (design §13–§16). Restartable types are the requests that got no
 * answer; every refusal by DEZI or failed check is final.
 */
enum DeziFailureType: string
{
    case UserInfoUnavailable = 'userinfo_unavailable';
    case UserInfoRefused = 'userinfo_refused';
    case UserInfoInvalid = 'userinfo_invalid';
    case UserInfoNotDecrypted = 'userinfo_not_decrypted';
    case EnvelopeInvalid = 'envelope_invalid';
    case StatementInvalid = 'statement_invalid';
    case StatementNotActive = 'statement_not_active';
    // A 404 from the status check: DEZI does not know the statement (design §15).
    case StatementUnknown = 'statement_unknown';
    // Any other 4xx from the status check: DEZI rejected the request.
    case StatusRequestRefused = 'status_request_refused';
    case StatusCheckUnavailable = 'status_check_unavailable';

    public function isRestartable(): bool
    {
        return in_array($this, [self::UserInfoUnavailable, self::StatusCheckUnavailable], true);
    }
}
