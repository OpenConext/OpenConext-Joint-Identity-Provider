<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\EngineBlock;

/**
 * EngineBlock's return URL (design §5, §13): the configured prefix, optionally followed by a query.
 * Checked as text at the start, and again by scheme, host, port and path before any redirect to it.
 */
final class ReturnUrl
{
    public static function isValid(string $url, string $prefix): bool
    {
        if (preg_match('/^[\x21-\x7E]+\z/', $url) !== 1 || str_contains($url, '#') || !str_starts_with($url, $prefix)) {
            return false;
        }

        $rest = substr($url, strlen($prefix));
        if ($rest !== '' && $rest[0] !== '?') {
            return false;
        }

        $actual = parse_url($url);
        $expected = parse_url($prefix);

        return is_array($actual) && is_array($expected)
            && ($actual['scheme'] ?? null) === 'https'
            && ($expected['scheme'] ?? null) === 'https'
            && strtolower($actual['host'] ?? '') === strtolower($expected['host'] ?? '')
            && ($actual['host'] ?? '') !== ''
            && ($actual['port'] ?? null) === ($expected['port'] ?? null)
            && ($actual['path'] ?? null) === ($expected['path'] ?? null)
            && !isset($actual['user'])
            && !isset($actual['pass'])
            && !isset($actual['fragment']);
    }
}
