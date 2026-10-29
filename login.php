<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_guest();

$email = '';
$errorMessage = flash('login_error');
$notice = flash('auth_notice');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    if (!csrf_verify()) {
        http_response_code(400);
        exit('The form expired or could not be verified. Reload the page and try again.');
    }

    $emailInput = $_POST['email'] ?? '';
    $passwordInput = $_POST['password'] ?? '';
    $email = is_string($emailInput) ? strtolower(trim($emailInput)) : '';
    $password = is_string($passwordInput) ? $passwordInput : '';

    $statement = db()->prepare(
        'SELECT id, name, email, password_hash, `role` FROM users WHERE email = :email LIMIT 1'
    );
    $statement->execute(['email' => $email]);
    $user = $statement->fetch();

    if (!is_array($user) || !password_verify($password, (string) $user['password_hash'])) {
        flash('login_error', 'Invalid email or password');
        $_SESSION['_old'] = ['email' => $email];
        redirect('login.php');
    }

    if (password_needs_rehash((string) $user['password_hash'], PASSWORD_DEFAULT)) {
        $newPasswordHash = password_hash($password, PASSWORD_DEFAULT);
        $updateHash = db()->prepare('UPDATE users SET password_hash = :password_hash WHERE id = :id');
        $updateHash->execute([
            'password_hash' => $newPasswordHash,
            'id' => (int) $user['id'],
        ]);
    }

    $updateLastLogin = db()->prepare(
        'UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id'
    );
    $updateLastLogin->execute(['id' => (int) $user['id']]);

    if (!session_regenerate_id(true)) {
        throw new RuntimeException('Unable to renew the session after login.');
    }

    $_SESSION['user_id'] = (int) $user['id'];
    $_SESSION['user_name'] = (string) $user['name'];
    $_SESSION['user_email'] = (string) $user['email'];
    $_SESSION['user_role'] = (string) $user['role'];
    $_SESSION['last_activity'] = time();
    unset($_SESSION['_old']);

    $intendedUrl = safe_intended_url($_SESSION['intended_url'] ?? null);
    unset($_SESSION['intended_url']);
    redirect($intendedUrl ?? 'dashboard.php');
}

$email = old('email', $email);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-shell">
    <section class="auth-card" aria-labelledby="login-title">
        <div class="auth-heading">
            <p class="eyebrow">SWD Auth</p>
            <h1 id="login-title">Welcome back</h1>
            <p class="subtitle">Sign in to continue to your account.</p>
        </div>

        <?php if ($notice !== null): ?>
            <p class="notice notice-success" role="status"><?= e($notice) ?></p>
        <?php endif; ?>
        <?php if ($errorMessage !== null): ?>
            <p class="notice notice-error" role="alert"><?= e($errorMessage) ?></p>
        <?php endif; ?>

        <form method="post" action="login.php">
            <?= csrf_field() ?>

            <label for="email">Email address</label>
            <input id="email" name="email" type="email" autocomplete="email" maxlength="254" required
                   value="<?= e($email) ?>">

            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required>

            <button type="submit">Sign in</button>
        </form>

        <p class="auth-footer">Don't have an account? <a href="register.php">Create one</a></p>
    </section>
</main>
</body>
</html>
