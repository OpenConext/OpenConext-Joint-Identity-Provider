<?php

declare(strict_types=1);

namespace MockDezi\Configuration;

final class Paths
{
    public static function resolve(string $base, string $path): string
    {
        return str_starts_with($path, '/') ? $path : rtrim($base, '/') . '/' . $path;
    }
}
