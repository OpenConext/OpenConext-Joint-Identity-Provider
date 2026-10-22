<?php

declare(strict_types=1);

namespace JointIdentityProvider\TestSp;

/**
 * HTML answers. Every value is escaped; the only style is a fixed inline block allowed by its CSP hash.
 */
final class Page
{
    private const string STYLE = 'body{font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;'
        . 'padding:0 1rem;color:#1d2433}header{border-bottom:3px solid #4f6d7a;margin-bottom:1rem}'
        . 'table{border-collapse:collapse}td,th{border:1px solid #ccd;padding:.25rem .5rem;text-align:left;'
        . 'vertical-align:top}.dezi{color:#05631d}.organisation{color:#7a5300}.refused{color:#a11}'
        . 'form{display:inline}';

    public static function send(int $status, string $title, string $body): void
    {
        http_response_code($status);
        header('Content-Type: text/html; charset=UTF-8');
        header('Cache-Control: no-store');
        header('Referrer-Policy: no-referrer');
        header('X-Frame-Options: DENY');
        header(sprintf(
            "Content-Security-Policy: default-src 'none'; style-src 'sha256-%s'; base-uri 'none';"
            . " form-action 'self'; frame-ancestors 'none'",
            base64_encode(hash('sha256', self::STYLE, true)),
        ));

        echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>JIP test SP: ', self::e($title),
            '</title><style>', self::STYLE, '</style></head><body><header><p>JointIdentityProvider (JIP) POC test',
            ' service provider</p></header><h1>', self::e($title), '</h1>', $body, '</body></html>';
    }

    public static function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }

    /**
     * @param array<string, list<string>> $attributes
     */
    public static function attributeTable(array $attributes): string
    {
        if ($attributes === []) {
            return '<p>None.</p>';
        }
        ksort($attributes);
        $rows = '';
        foreach ($attributes as $name => $values) {
            $cells = array_map(static fn (string $v): string => '<code>' . self::e($v) . '</code>', $values);
            $rows .= '<tr><td><code>' . self::e($name) . '</code></td><td>' . implode('<br>', $cells) . '</td></tr>';
        }

        return '<table><tr><th>Name</th><th>Values</th></tr>' . $rows . '</table>';
    }
}
