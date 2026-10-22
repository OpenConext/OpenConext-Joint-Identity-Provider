<?php

declare(strict_types=1);

namespace JointIdentityProvider\TestSp\Tests;

use JointIdentityProvider\TestSp\Access;
use JointIdentityProvider\TestSp\AccessDecision;
use JointIdentityProvider\TestSp\AccessRules;
use JointIdentityProvider\TestSp\Decision;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AccessDecisionTest extends TestCase
{
    private const string FLAG = 'urn:mace:govroam.nl:attribute-def:dezi:login';
    private const string NUMBER = 'urn:mace:govroam.nl:attribute-def:dezi:dezi-nummer';
    private const string SUBSCRIBER = 'urn:mace:govroam.nl:attribute-def:dezi:abonnee-nummer';
    private const string ROLE = 'urn:mace:govroam.nl:attribute-def:dezi:rol-code';
    private const string ORGANISATION_NUMBER = 'urn:mace:govroam.nl:attribute-def:organisation-dezi-nummer';

    public function testVerifiedWithPermittedSubscriberAndRoleGrantsDeziAccess(): void
    {
        $decision = self::decide(self::verified());

        self::assertSame(Access::Dezi, $decision->access);
        self::assertSame('900000001', $decision->deziNumber);
        self::assertSame('90000001', $decision->subscriber);
        self::assertSame('01.000', $decision->role);
    }

    public function testSkippedFlagGivesOrganisationAccessOnly(): void
    {
        self::assertSame(Access::Organisation, self::decide([self::FLAG => ['skipped']])->access);
    }

    public function testMissingFlagGivesOrganisationAccessEvenWithDeziAttributes(): void
    {
        $attributes = self::verified();
        unset($attributes[self::FLAG]);

        self::assertSame(Access::Organisation, self::decide($attributes)->access);
    }

    public function testSkippedWithForgedDeziAttributesGrantsNoDeziAccess(): void
    {
        $attributes = self::verified();
        $attributes[self::FLAG] = ['skipped'];

        $decision = self::decide($attributes);

        self::assertSame(Access::Organisation, $decision->access);
        self::assertNull($decision->deziNumber);
    }

    public function testOrganisationNumberNeverStandsInForADeziResult(): void
    {
        $decision = self::decide([self::ORGANISATION_NUMBER => ['900000001']]);

        self::assertSame(Access::Organisation, $decision->access);
        self::assertNull($decision->deziNumber);
    }

    /**
     * @return iterable<string, array{array<string, list<string>>}>
     */
    public static function refusedLogins(): iterable
    {
        $verified = self::verified();

        yield 'verified and skipped' => [[self::FLAG => ['verified', 'skipped']] + $verified];
        yield 'flag twice verified' => [[self::FLAG => ['verified', 'verified']] + $verified];
        yield 'unknown flag' => [[self::FLAG => ['yes']] + $verified];
        yield 'empty flag value' => [[self::FLAG => ['']] + $verified];
        yield 'no DEZI number' => [array_diff_key($verified, [self::NUMBER => true])];
        yield 'two DEZI numbers' => [[self::NUMBER => ['900000001', '900000002']] + $verified];
        yield 'empty DEZI number' => [[self::NUMBER => ['']] + $verified];
        yield 'whitespace DEZI number' => [[self::NUMBER => ['  ']] + $verified];
        yield 'no subscriber' => [array_diff_key($verified, [self::SUBSCRIBER => true])];
        yield 'two subscribers' => [[self::SUBSCRIBER => ['90000001', '90000002']] + $verified];
        yield 'two roles, one privileged' => [[self::ROLE => ['01.000', '99.999']] + $verified];
        yield 'empty role' => [[self::ROLE => ['']] + $verified];
        yield 'no role while required' => [array_diff_key($verified, [self::ROLE => true])];
        yield 'role 00.000 not permitted' => [[self::ROLE => ['00.000']] + $verified];
        yield 'role in another format' => [[self::ROLE => ['1.000']] + $verified];
        yield 'subscriber not permitted' => [[self::SUBSCRIBER => ['90000002']] + $verified];
    }

    /**
     * @param array<string, list<string>> $attributes
     */
    #[DataProvider('refusedLogins')]
    public function testRefused(array $attributes): void
    {
        $decision = self::decide($attributes);

        self::assertSame(Access::Refused, $decision->access);
        self::assertNull($decision->deziNumber);
    }

    public function testRoleIsOptionalWhenTheApplicationDoesNotRequireOne(): void
    {
        $rules = new AccessRules(
            'urn:mace:govroam.nl:attribute-def:dezi:',
            self::FLAG,
            self::NUMBER,
            self::SUBSCRIBER,
            self::ROLE,
            ['90000001'],
            false,
            ['01.000'],
        );

        $decision = (new AccessDecision($rules))->decide(array_diff_key(self::verified(), [self::ROLE => true]));

        self::assertSame(Access::Dezi, $decision->access);
        self::assertNull($decision->role);
    }

    public function testReasonsHoldNoAttributeValues(): void
    {
        foreach (self::refusedLogins() as [$attributes]) {
            $reason = self::decide($attributes)->reason;
            self::assertDoesNotMatchRegularExpression('/\d{5,}/', $reason);
        }
    }

    /**
     * @param array<string, list<string>> $attributes
     */
    private static function decide(array $attributes): Decision
    {
        return (new AccessDecision(AccessRules::fromArray([
            'reserved_prefix' => 'urn:mace:govroam.nl:attribute-def:dezi:',
            'login_flag' => self::FLAG,
            'dezi_number' => self::NUMBER,
            'subscriber' => self::SUBSCRIBER,
            'role' => self::ROLE,
            'permitted_subscribers' => ['90000001'],
            'role_required' => true,
            'permitted_roles' => ['01.000'],
        ])))->decide($attributes);
    }

    /**
     * @return array<string, list<string>>
     */
    private static function verified(): array
    {
        return [
            self::FLAG => ['verified'],
            self::NUMBER => ['900000001'],
            self::SUBSCRIBER => ['90000001'],
            self::ROLE => ['01.000'],
            'urn:mace:dir:attribute-def:uid' => ['anna'],
        ];
    }
}
