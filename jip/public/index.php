<?php

use JointIdentityProvider\Kernel;

require_once dirname(__DIR__).'/vendor/autoload_runtime.php';

return static function (array $context) {
    // Symfony Runtime sets umask 0 in debug mode, which would make var/ files world-writable.
    umask(0o027);

    return new Kernel($context['APP_ENV'], (bool) $context['APP_DEBUG']);
};
