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
        exit('Forbidden');
    }

    return $user;
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
