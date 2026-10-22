<?php

declare(strict_types=1);

namespace JointIdentityProvider\TestSp;

/**
 * The application acceptance contract of design §7, applied to the attributes of an assertion whose signature,
 * issuer, audience, destination, InResponseTo and validity window have already been checked (item 1).
 *
 * The decision never reads the organisation's DEZI-number attribute, the authentication context or any setting
 * in Manage: only the login flag and the DEZI attributes under the reserved names decide.
 */
final readonly class AccessDecision
{
    public const string VERIFIED = 'verified';
    public const string SKIPPED = 'skipped';

    public function __construct(private AccessRules $rules)
    {
    }

    /**
     * @param array<string, list<string>> $attributes
     */
    public function decide(array $attributes): Decision
    {
        $flag = $attributes[$this->rules->loginFlag] ?? [];
        if (count($flag) > 1) {
            return Decision::refused('the login flag has more than one value');
        }
        $value = $flag[0] ?? null;
        if ($value === null || $value === self::SKIPPED) {
            return Decision::organisation($value === null
                ? 'no login flag: login without DEZI; DEZI attributes are not used'
                : 'login flag skipped: login without DEZI; DEZI attributes are not used');
        }
        if ($value !== self::VERIFIED) {
            return Decision::refused('the login flag has an unknown value');
        }

        $deziNumber = self::single($attributes[$this->rules->deziNumber] ?? []);
        if ($deziNumber === null) {
            return Decision::refused('verified, but not exactly one non-empty DEZI number');
        }
        $subscriber = self::single($attributes[$this->rules->subscriber] ?? []);
        if ($subscriber === null) {
            return Decision::refused('verified, but not exactly one non-empty subscriber number');
        }

        $roles = $attributes[$this->rules->role] ?? [];
        $role = self::single($roles);
        if ($roles !== [] && $role === null) {
            return Decision::refused('the role code is malformed or has more than one value');
        }
        if ($role === null && $this->rules->roleRequired) {
            return Decision::refused('verified, but the profile has no role code and this application requires one');
        }

        if (!in_array($subscriber, $this->rules->permittedSubscribers, true)) {
            return Decision::refused('the subscriber is not permitted by this application');
        }
        if ($role !== null && !in_array($role, $this->rules->permittedRoles, true)) {
            return Decision::refused('the role code is not on this application\'s list of permitted roles');
        }

        return Decision::dezi($deziNumber, $subscriber, $role, 'verified, with a permitted subscriber and role');
    }

    /**
     * Exactly one value that is not empty or only whitespace; compared later as an exact string.
     *
     * @param list<string> $values
     */
    private static function single(array $values): ?string
    {
        return count($values) === 1 && trim($values[0]) !== '' ? $values[0] : null;
    }
}
