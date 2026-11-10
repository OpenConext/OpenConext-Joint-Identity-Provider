<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Login;

enum BrowserOutcomeType
{
    case Unknown;
    case InProgress;
    case Failure;
    case Redirect;
}
