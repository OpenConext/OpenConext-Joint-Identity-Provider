<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Core\Logging;

use JointIdentityProvider\Core\Logging\LineLogger;
use PHPUnit\Framework\TestCase;
use Psr\Log\InvalidArgumentException;
use stdClass;

/**
 * JIP's application log lines (design §20).
 */
final class LineLoggerTest extends TestCase
{
    /** @var list<string> */
    private array $lines = [];

    public function test_a_line_carries_the_label_and_level(): void
    {
        $this->logger('jip', 'info')->warning('JIP start {log_id}: refused', ['log_id' => 'ab12']);

        self::assertSame(['jip.WARNING: JIP start ab12: refused'], $this->lines);
    }

    public function test_records_below_the_minimum_level_are_dropped(): void
    {
        $logger = $this->logger('jip.framework', 'warning');
        $logger->info('Matched route');
        $logger->debug('Request');
        $logger->error('Uncaught');

        self::assertSame(['jip.framework.ERROR: Uncaught'], $this->lines);
    }

    public function test_only_named_scalar_placeholders_are_replaced_and_the_context_is_never_written(): void
    {
        $this->logger('jip', 'info')->info('{a} {b} {c} {missing}', [
            'a' => 'x',
            'b' => 42,
            'c' => ['secret-in-array'],
            'd' => 'secret-unreferenced',
            'exception' => new stdClass(),
        ]);

        self::assertSame(['jip.INFO: x 42 {c} {missing}'], $this->lines);
    }

    public function test_query_strings_of_urls_are_removed(): void
    {
        $this->logger('jip.framework', 'warning')->error(
            'GET https://jip.dev.openconext.local/oidc/callback?code=abc&state=def failed; then'
            . ' http://x/interrupt?nonce=ghi#frag and "https://y/p?q=1"',
        );

        self::assertSame([
            'jip.framework.ERROR: GET https://jip.dev.openconext.local/oidc/callback?[query removed] failed; then'
            . ' http://x/interrupt?[query removed]#frag and "https://y/p?[query removed]"',
        ], $this->lines);
    }

    public function test_line_breaks_cannot_forge_another_line(): void
    {
        $this->logger('jip', 'info')->info("a\r\njip.ERROR: {v}", ['v' => "b\nc"]);

        self::assertSame(['jip.INFO: a  jip.ERROR: b c'], $this->lines);
    }

    public function test_unknown_levels_are_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->logger('jip', 'info')->log('verbose', 'x');
    }

    public function test_an_unknown_minimum_level_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->logger('jip', 'loud');
    }

    private function logger(string $label, string $minLevel): LineLogger
    {
        return new LineLogger($label, $minLevel, function (string $line): void {
            $this->lines[] = $line;
        });
    }
}
