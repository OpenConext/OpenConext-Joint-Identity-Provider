<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Logging;

use Closure;
use Psr\Log\AbstractLogger;
use Psr\Log\InvalidArgumentException;
use Stringable;

/**
 * One line per record through PHP's error log (the container's error stream), labelled `<label>.<LEVEL>:`
 * (design §20). Only scalar placeholders are interpolated; the context is never serialised, and query strings
 * of URLs in the message are removed, because they can carry live authentication values.
 */
final class LineLogger extends AbstractLogger
{
    private const array LEVELS = [
        'debug' => 0,
        'info' => 1,
        'notice' => 2,
        'warning' => 3,
        'error' => 4,
        'critical' => 5,
        'alert' => 6,
        'emergency' => 7,
    ];
    private const string QUERY = '~(https?://[^\s"\'?#<>]*)\?[^\s"\'#<>]*~';

    /** @var Closure(string): void */
    private Closure $writer;

    /**
     * @param (callable(string): void)|null $writer receives each line; PHP's error_log() when null
     */
    public function __construct(private string $label, private string $minLevel, ?callable $writer = null)
    {
        if (!isset(self::LEVELS[$minLevel])) {
            throw new InvalidArgumentException('Unknown minimum log level.');
        }
        $this->writer = $writer !== null
            ? $writer(...)
            : static function (string $line): void {
                error_log($line);
            };
    }

    /**
     * @param array<mixed> $context
     */
    public function log(mixed $level, string|Stringable $message, array $context = []): void
    {
        if (!is_string($level) || !isset(self::LEVELS[$level])) {
            throw new InvalidArgumentException('Unknown log level.');
        }
        if (self::LEVELS[$level] < self::LEVELS[$this->minLevel]) {
            return;
        }

        $replacements = [];
        foreach ($context as $key => $value) {
            if (is_scalar($value) || $value instanceof Stringable) {
                $replacements['{' . $key . '}'] = (string) $value;
            }
        }
        $text = strtr((string) $message, $replacements);
        $text = (string) preg_replace(self::QUERY, '$1?[query removed]', $text);
        $text = str_replace(["\r", "\n"], ' ', $text);

        ($this->writer)(sprintf('%s.%s: %s', $this->label, strtoupper($level), $text));
    }
}
