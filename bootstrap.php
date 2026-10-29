<?php
declare(strict_types=1);

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/src/db.php';
require_once __DIR__ . '/src/helpers.php';
require_once __DIR__ . '/src/csrf.php';
require_once __DIR__ . '/src/auth.php';

error_reporting(E_ALL);
ini_set('display_errors', APP_ENV === 'development' ? '1' : '0');
ini_set('display_startup_errors', APP_ENV === 'development' ? '1' : '0');

$isHttps = isset($_SERVER['HTTPS'])
    && $_SERVER['HTTPS'] !== ''
    && strtolower((string) $_SERVER['HTTPS']) !== 'off';

if (PHP_SAPI !== 'cli' && APP_ENV !== 'development' && !$isHttps) {
    $requestUri = $_SERVER['REQUEST_URI'] ?? '/';
    if (!is_string($requestUri) || $requestUri === '' || $requestUri[0] !== '/') {
        $requestUri = '/';
    }

    $host = $_SERVER['SERVER_NAME'] ?? '';
    if (!is_string($host) || preg_match('/\A[a-zA-Z0-9.-]+\z/', $host) !== 1) {
        http_response_code(400);
        exit('Invalid host.');
    }

    header('Location: https://' . $host . $requestUri, true, 301);
    exit;
}

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

if ($isHttps) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.use_strict_mode', '1');
    session_name('SWDSESSID');

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => APP_ENV === 'development' ? $isHttps : true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    session_start();
}
