<?php

declare(strict_types=1);

namespace JointIdentityProvider\TestSp;

enum Access: string
{
    case Dezi = 'dezi';
    case Organisation = 'organisation';
    case Refused = 'refused';

    public function label(): string
    {
        return match ($this) {
            self::Dezi => 'DEZI-based access granted',
            self::Organisation => 'Organisation-level access only (login without DEZI)',
            self::Refused => 'Access refused',
        };
    }
}
