<?php

declare(strict_types=1);

use JointIdentityProvider\TestSp\Application;
use JointIdentityProvider\TestSp\Configuration;

require dirname(__DIR__) . '/vendor/autoload.php';

try {
    try {
        $configuration = Configuration::load(dirname(__DIR__) . '/config/test-sp.php');
    } catch (InvalidArgumentException $exception) {
        Application::configurationFailure($exception);

        return;
    }
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $path = parse_url(is_string($_SERVER['REQUEST_URI'] ?? null) ? $_SERVER['REQUEST_URI'] : '/', PHP_URL_PATH);
    (new Application($configuration))
        ->handle(is_string($method) ? $method : 'GET', is_string($path) ? $path : '/');
} catch (Throwable $exception) {
    Application::failSafe($exception);
}
