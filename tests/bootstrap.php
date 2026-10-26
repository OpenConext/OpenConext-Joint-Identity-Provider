<?php

declare(strict_types=1);

use Symfony\Component\Dotenv\Dotenv;

require dirname(__DIR__) . '/vendor/autoload.php';

// Same umask as the front controllers: nothing under var/ is world-accessible.
umask(0o027);

(new Dotenv())->bootEnv(dirname(__DIR__) . '/.env');
