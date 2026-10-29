<?php
declare(strict_types=1);

function safe_intended_url(mixed $url): ?string
{
    if (
        !is_string($url)
        || $url === ''
        || $url[0] !== '/'
        || str_starts_with($url, '//')
        || str_contains($url, '\\')
        || preg_match('/[\x00-\x20\x7f]/', $url) === 1
    ) {
        return null;
    }

    $parts = parse_url($url);
    if (
        $parts === false
        || isset($parts['scheme'])
        || isset($parts['host'])
        || isset($parts['user'])
        || isset($parts['pass'])
        || !isset($parts['path'])
        || $parts['path'] === ''
        || $parts['path'][0] !== '/'
    ) {
        return null;
    }

    return $url;
}

function current_user(): ?array
{
    $userId = $_SESSION['user_id'] ?? null;
    if (!is_int($userId) || $userId < 1) {
        return null;
    }

    $now = time();
    $lastActivity = $_SESSION['last_activity'] ?? null;
    if (!is_int($lastActivity) || $now - $lastActivity >= 1800) {
        end_session_with_flash('You were logged out after 30 minutes of inactivity.');
    }

    $statement = db()->prepare(
        'SELECT id, name, email, `role`, created_at, last_login_at FROM users WHERE id = :id LIMIT 1'
    );
    $statement->execute(['id' => $userId]);
    $user = $statement->fetch();

    if (!is_array($user)) {
        $_SESSION = [];
        return null;
    }

    $_SESSION['user_role'] = (string) $user['role'];
    $_SESSION['last_activity'] = $now;

    return $user;
}

function require_login(): array
{
    $user = current_user();

    if ($user === null) {
        $requestedUrl = safe_intended_url($_SERVER['REQUEST_URI'] ?? null);
        if ($requestedUrl !== null) {
            $_SESSION['intended_url'] = $requestedUrl;
        }

        redirect('login.php');
    }

    return $user;
}

function require_guest(): void
{
    if (current_user() !== null) {
        redirect('dashboard.php');
    }
}

function require_role(string $role): array
{
    $user = require_login();

    if ($role !== 'admin' || $user['role'] !== $role) {
        http_response_code(403);
        $scriptDirectory = str_replace('\\', '/', dirname((string) ($_SERVER['SCRIPT_NAME'] ?? '')));
        $basePath = str_ends_with($scriptDirectory, '/admin') ? '../' : '';
        echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<title>Access denied</title><link rel="stylesheet" href="'
            . e($basePath . 'assets/auth.css') . '">'
            . '</head><body><main class="auth-shell"><section class="auth-card">'
            . '<p class="eyebrow">403 | Access denied</p><h1>Restricted area</h1>'
            . '<p class="subtitle">You do not have permission to view this page.</p>'
            . '<p class="auth-footer"><a href="' . e($basePath . 'dashboard.php')
            . '">Return to dashboard</a></p>'
            . '</section></main></body></html>';
        exit;
    }

    return $user;
}

function login_throttle_minutes(string $email, ?string $ipAddress): int
{
    $remainingSeconds = 0;
    $db = db();

    $emailAttempt = $db->prepare(
        'SELECT GREATEST(0, 900 - TIMESTAMPDIFF(SECOND, attempted_at, CURRENT_TIMESTAMP)) '
        . 'AS remaining_seconds FROM login_attempts '
        . 'WHERE email = :email AND attempted_at >= CURRENT_TIMESTAMP - INTERVAL 15 MINUTE '
        . 'ORDER BY attempted_at DESC LIMIT 1 OFFSET 4'
    );
    $emailAttempt->execute(['email' => $email]);
    $emailResult = $emailAttempt->fetchColumn();
    if ($emailResult !== false) {
        $remainingSeconds = max($remainingSeconds, (int) $emailResult);
    }

    if ($ipAddress !== null) {
        $ipAttempt = $db->prepare(
            'SELECT GREATEST(0, 900 - TIMESTAMPDIFF(SECOND, attempted_at, CURRENT_TIMESTAMP)) '
            . 'AS remaining_seconds FROM login_attempts '
            . 'WHERE ip_address = :ip_address '
            . 'AND attempted_at >= CURRENT_TIMESTAMP - INTERVAL 15 MINUTE '
            . 'ORDER BY attempted_at DESC LIMIT 1 OFFSET 4'
        );
        $ipAttempt->execute(['ip_address' => $ipAddress]);
        $ipResult = $ipAttempt->fetchColumn();
        if ($ipResult !== false) {
            $remainingSeconds = max($remainingSeconds, (int) $ipResult);
        }
    }

    return (int) ceil($remainingSeconds / 60);
}

function record_login_failure(string $email, ?string $ipAddress): void
{
    $statement = db()->prepare(
        'INSERT INTO login_attempts (email, ip_address) VALUES (:email, :ip_address)'
    );
    $statement->execute([
        'email' => $email,
        'ip_address' => $ipAddress,
    ]);
}

function clear_login_attempts(string $email, ?string $ipAddress): void
{
    if ($ipAddress === null) {
        $statement = db()->prepare('DELETE FROM login_attempts WHERE email = :email');
        $statement->execute(['email' => $email]);
        return;
    }

    $statement = db()->prepare(
        'DELETE FROM login_attempts WHERE email = :email OR ip_address = :ip_address'
    );
    $statement->execute([
        'email' => $email,
        'ip_address' => $ipAddress,
    ]);
}

function end_session_with_flash(string $message): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies') === '1') {
        $cookie = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $cookie['path'],
            'domain' => $cookie['domain'],
            'secure' => $cookie['secure'],
            'httponly' => $cookie['httponly'],
            'samesite' => $cookie['samesite'] ?? 'Lax',
        ]);
    }

    session_destroy();
    session_start();
    flash('auth_notice', $message);
    redirect('login.php');
}
