<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Start;

enum BindingStatus
{
    case Absent;
    case Single;
    case Malformed;
}
