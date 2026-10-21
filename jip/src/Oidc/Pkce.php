<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc;

use JointIdentityProvider\Oidc\Jose\Base64Url;

/**
 * PKCE with `S256` (RFC 7636). The verifier is 256 random bits: 43 characters.
 */
final class Pkce
{
    public const string METHOD = 'S256';

    public static function verifier(): string
    {
        return Base64Url::randomToken();
    }

    public static function challenge(string $verifier): string
    {
        return Base64Url::encode(hash('sha256', $verifier, true));
    }
}
