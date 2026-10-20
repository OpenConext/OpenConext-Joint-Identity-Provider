<?php

declare(strict_types=1);

use Symfony\Component\Dotenv\Dotenv;

require dirname(__DIR__) . '/vendor/autoload.php';

umask(0o027);

(new Dotenv())->bootEnv(dirname(__DIR__) . '/.env');
