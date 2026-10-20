<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Core\Start;

use JointIdentityProvider\Core\Start\BindingInput;
use JointIdentityProvider\Core\Start\BindingStatus;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The binding-attribute table of design §4.
 */
final class BindingInputTest extends TestCase
{
    private const string NAME = 'urn:example:organisation-number';

    /**
     * @param array<string, mixed> $attributes
     */
    #[DataProvider('cases')]
    public function test_the_binding_attribute_is_classified(array $attributes, BindingStatus $status, string $value): void
    {
        $input = BindingInput::classify($attributes, self::NAME);

        self::assertSame($status, $input->status);
        self::assertSame($value, $input->value);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, BindingStatus, string}>
     */
    public static function cases(): iterable
    {
        yield 'absent' => [['urn:other' => ['x']], BindingStatus::Absent, ''];
        yield 'an empty list' => [[self::NAME => []], BindingStatus::Absent, ''];
        yield 'one empty string' => [[self::NAME => ['']], BindingStatus::Absent, ''];
        yield 'one non-empty string' => [[self::NAME => ['123456789']], BindingStatus::Single, '123456789'];
        yield 'one string kept exactly, leading zeros and dots included' => [[self::NAME => ['007.010']], BindingStatus::Single, '007.010'];
        yield 'one value under a non-zero key' => [[self::NAME => [3 => '123456789']], BindingStatus::Single, '123456789'];
        yield 'two values' => [[self::NAME => ['123456789', '987654321']], BindingStatus::Malformed, ''];
        yield 'two equal values' => [[self::NAME => ['123456789', '123456789']], BindingStatus::Malformed, ''];
        yield 'an empty and a non-empty value' => [[self::NAME => ['', '123456789']], BindingStatus::Malformed, ''];
        yield 'a value of only spaces' => [[self::NAME => ['   ']], BindingStatus::Malformed, ''];
        yield 'a value of only whitespace' => [[self::NAME => ["\t\n"]], BindingStatus::Malformed, ''];
        yield 'an integer value' => [[self::NAME => [123456789]], BindingStatus::Malformed, ''];
        yield 'a null value' => [[self::NAME => [null]], BindingStatus::Malformed, ''];
        yield 'a nested list' => [[self::NAME => [['123456789']]], BindingStatus::Malformed, ''];
        yield 'a string instead of a list' => [[self::NAME => '123456789'], BindingStatus::Malformed, ''];
        yield 'null instead of a list' => [[self::NAME => null], BindingStatus::Malformed, ''];
    }
}
