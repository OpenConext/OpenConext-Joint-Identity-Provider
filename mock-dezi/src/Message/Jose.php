<?php

declare(strict_types=1);

namespace MockDezi\Message;

use RuntimeException;

/**
 * Builds compact JWS (RS256) and JWE (RSA-OAEP or RSA-OAEP-256; A256CBC-HS512 or A256GCM) directly on OpenSSL.
 * The mock thereby needs no ext-gmp, and its messages are produced independently of the JOSE library that JIP
 * uses to check them. The wrong algorithms exist only for the scenarios.
 */
final class Jose
{
    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header
     */
    public static function sign(array $claims, string $privateKeyPem, array $header): string
    {
        $input = self::base64Url(self::json(['alg' => 'RS256'] + $header)) . '.' . self::base64Url(self::json($claims));
        if (!openssl_sign($input, $signature, $privateKeyPem, OPENSSL_ALGO_SHA256) || !is_string($signature)) {
            throw new RuntimeException('RS256 signing failed');
        }

        return $input . '.' . self::base64Url($signature);
    }

    /**
     * An unsecured JWS (alg "none"): header and payload, empty signature.
     *
     * @param array<string, mixed> $claims
     */
    public static function unsigned(array $claims): string
    {
        return self::base64Url(self::json(['alg' => 'none', 'typ' => 'JWT'])) . '.'
            . self::base64Url(self::json($claims)) . '.';
    }

    /**
     * Verifies an RS256 compact JWS with a public key or certificate. Returns the protected header and the
     * payload, or null when the token is malformed, not RS256 or not signed by that key.
     *
     * @return array{array<mixed>, string}|null
     */
    public static function verifyRs256(string $compact, string $publicKeyPem): ?array
    {
        $parts = explode('.', $compact);
        if (count($parts) !== 3) {
            return null;
        }
        $header = self::decodeJson($parts[0]);
        $payload = self::base64UrlDecode($parts[1]);
        $signature = self::base64UrlDecode($parts[2]);
        if ($header === null || $payload === null || $signature === null || ($header['alg'] ?? null) !== 'RS256') {
            return null;
        }
        $valid = openssl_verify($parts[0] . '.' . $parts[1], $signature, $publicKeyPem, OPENSSL_ALGO_SHA256);

        return $valid === 1 ? [$header, $payload] : null;
    }

    /**
     * @param string $recipient a PEM public key or certificate
     */
    public static function encrypt(string $payload, string $recipient, string $alg, string $enc, string $kid): string
    {
        $header = self::base64Url(self::json(['alg' => $alg, 'enc' => $enc, 'kid' => $kid]));
        [$cek, $iv, $ciphertext, $tag] = match ($enc) {
            'A256CBC-HS512' => self::a256CbcHs512($payload, $header),
            'A256GCM' => self::a256Gcm($payload, $header),
            default => throw new RuntimeException('Unsupported enc ' . $enc),
        };
        $digest = match ($alg) {
            'RSA-OAEP' => 'sha1',
            'RSA-OAEP-256' => 'sha256',
            default => throw new RuntimeException('Unsupported alg ' . $alg),
        };
        if (
            !openssl_public_encrypt($cek, $encryptedKey, $recipient, OPENSSL_PKCS1_OAEP_PADDING, $digest)
            || !is_string($encryptedKey)
        ) {
            throw new RuntimeException('RSA-OAEP key encryption failed');
        }

        return implode('.', [
            $header,
            self::base64Url($encryptedKey),
            self::base64Url($iv),
            self::base64Url($ciphertext),
            self::base64Url($tag),
        ]);
    }

    public static function publicKeyPem(string $privateKeyPem): string
    {
        $key = openssl_pkey_get_private($privateKeyPem);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if ($details === false || !is_string($details['key'] ?? null)) {
            throw new RuntimeException('Cannot derive the public key');
        }

        return $details['key'];
    }

    public static function base64Url(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $encoded): ?string
    {
        if (preg_match('/^[A-Za-z0-9_-]*$/', $encoded) !== 1) {
            return null;
        }
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }

    /**
     * @return array<mixed>|null
     */
    public static function decodeJson(string $encoded): ?array
    {
        $json = self::base64UrlDecode($encoded);
        $value = $json === null ? null : json_decode($json, true, 16);

        return is_array($value) ? $value : null;
    }

    /**
     * @param array<mixed> $value
     */
    public static function json(array $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    public static function randomToken(): string
    {
        return self::base64Url(random_bytes(32));
    }

    public static function uuidV4(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        $hex = bin2hex($bytes);

        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20),
        );
    }

    /**
     * RFC 7518 §5.2: AES-256-CBC with HMAC-SHA-512, a 64-byte key (MAC key first).
     *
     * @return array{string, string, string, string} CEK, IV, ciphertext, tag
     */
    private static function a256CbcHs512(string $payload, string $aad): array
    {
        $cek = random_bytes(64);
        $iv = random_bytes(16);
        $ciphertext = openssl_encrypt($payload, 'aes-256-cbc', substr($cek, 32), OPENSSL_RAW_DATA, $iv);
        if ($ciphertext === false) {
            throw new RuntimeException('AES-256-CBC encryption failed');
        }
        $mac = hash_hmac('sha512', $aad . $iv . $ciphertext . pack('J', strlen($aad) * 8), substr($cek, 0, 32), true);

        return [$cek, $iv, $ciphertext, substr($mac, 0, 32)];
    }

    /**
     * @return array{string, string, string, string} CEK, IV, ciphertext, tag
     */
    private static function a256Gcm(string $payload, string $aad): array
    {
        $cek = random_bytes(32);
        $iv = random_bytes(12);
        $ciphertext = openssl_encrypt($payload, 'aes-256-gcm', $cek, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
        if ($ciphertext === false) {
            throw new RuntimeException('AES-256-GCM encryption failed');
        }

        return [$cek, $iv, $ciphertext, $tag];
    }
}
