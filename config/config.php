<?php
declare(strict_types=1);

$env = static function (string $name, string $default): string {
    $value = getenv($name);

    return $value === false ? $default : $value;
};

define('APP_ENV', $env('APP_ENV', 'production'));
define('DB_HOST', $env('DB_HOST', '127.0.0.1'));
define('DB_PORT', $env('DB_PORT', '3306'));
define('DB_NAME', $env('DB_NAME', 'swd_auth'));
define('DB_USER', $env('DB_USER', 'root'));
define('DB_PASS', $env('DB_PASS', ''));
