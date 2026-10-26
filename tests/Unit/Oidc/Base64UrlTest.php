<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Oidc;

use JointIdentityProvider\Oidc\Jose\Base64Url;
use PHPUnit\Framework\TestCase;

final class Base64UrlTest extends TestCase
{
    public function test_tokens_and_base64url_reject_a_trailing_newline(): void
    {
        $token = Base64Url::randomToken();
        self::assertTrue(Base64Url::isRandomToken($token));
        self::assertFalse(Base64Url::isRandomToken($token . "\n"));
        self::assertSame('a', Base64Url::decode('YQ'));
        self::assertNull(Base64Url::decode("YQ\n"));
    }
}
