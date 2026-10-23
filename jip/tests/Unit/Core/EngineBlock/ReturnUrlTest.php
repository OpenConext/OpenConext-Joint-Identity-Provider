<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Core\EngineBlock;

use JointIdentityProvider\Core\EngineBlock\ReturnUrl;
use PHPUnit\Framework\TestCase;

final class ReturnUrlTest extends TestCase
{
    public function test_a_return_url_with_a_trailing_newline_is_refused(): void
    {
        $prefix = 'https://engine.example/return';
        self::assertTrue(ReturnUrl::isValid($prefix . '?ID=abc', $prefix));
        self::assertFalse(ReturnUrl::isValid($prefix . "?ID=abc\n", $prefix));
    }
}
