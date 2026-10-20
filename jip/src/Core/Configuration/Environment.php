<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

enum Environment: string
{
    case Mock = 'mock';
    case Acceptance = 'acceptance';
    case Production = 'production';
}
