<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Jose;

final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Strict base64url without padding; null for any other input.
     */
    public static function decode(string $encoded): ?string
    {
        if (preg_match('/^[A-Za-z0-9_-]*\z/', $encoded) !== 1) {
            return null;
        }
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }

    /**
     * 256 random bits, base64url without padding: 43 characters.
     */
    public static function randomToken(): string
    {
        return self::encode(random_bytes(32));
    }

    public static function isRandomToken(string $value): bool
    {
        return preg_match('/^[A-Za-z0-9_-]{43}\z/', $value) === 1;
    }
}
