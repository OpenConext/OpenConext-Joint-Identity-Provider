<?php

declare(strict_types=1);

namespace JointIdentityProvider\TestSp;

use InvalidArgumentException;

/**
 * The application's own rules (design §7 items 3–7) and the attribute names it reads.
 */
final readonly class AccessRules
{
    /**
     * @param list<string> $permittedSubscribers
     * @param list<string> $permittedRoles
     */
    public function __construct(
        public string $reservedPrefix,
        public string $loginFlag,
        public string $deziNumber,
        public string $subscriber,
        public string $role,
        public array $permittedSubscribers,
        public bool $roleRequired,
        public array $permittedRoles,
    ) {
        foreach ([$loginFlag, $deziNumber, $subscriber, $role] as $name) {
            if (!str_starts_with($name, $reservedPrefix)) {
                throw new InvalidArgumentException('Every DEZI attribute name must lie inside the reserved prefix.');
            }
        }
    }

    /**
     * @param array<mixed> $config
     */
    public static function fromArray(array $config): self
    {
        $string = static function (string $key) use ($config): string {
            $value = $config[$key] ?? null;
            if (!is_string($value) || $value === '') {
                throw new InvalidArgumentException(sprintf('%s must be a non-empty string.', $key));
            }

            return $value;
        };
        $list = static function (string $key) use ($config): array {
            $value = $config[$key] ?? null;
            if (!is_array($value) || !array_is_list($value)) {
                throw new InvalidArgumentException(sprintf('%s must be a list.', $key));
            }
            $strings = [];
            foreach ($value as $item) {
                if (!is_string($item) || $item === '') {
                    throw new InvalidArgumentException(sprintf('%s must hold non-empty strings.', $key));
                }
                $strings[] = $item;
            }

            return $strings;
        };
        $roleRequired = $config['role_required'] ?? null;
        if (!is_bool($roleRequired)) {
            throw new InvalidArgumentException('role_required must be true or false.');
        }

        return new self(
            $string('reserved_prefix'),
            $string('login_flag'),
            $string('dezi_number'),
            $string('subscriber'),
            $string('role'),
            $list('permitted_subscribers'),
            $roleRequired,
            $list('permitted_roles'),
        );
    }
}
