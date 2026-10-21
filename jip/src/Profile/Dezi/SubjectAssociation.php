<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

/**
 * How the UserInfo envelope is tied to the ID token's subject (design §5, §14). A supplied envelope
 * `sub` must always equal the ID token's `sub`; `dezi_nummer` never stands in for it.
 */
enum SubjectAssociation: string
{
    // Standard OIDC: the envelope must carry `sub`.
    case EnvelopeSub = 'envelope_sub';
    // Specification v0.7: no envelope `sub`; DEZI ties UserInfo to the access token it validates. Only with
    // an explicitly approved CIBG contract (design §10).
    case AccessToken = 'access_token';
}
