<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

$user = require_login();
$profileError = flash('profile_error');
$profileSuccess = flash('profile_success');
$passwordError = flash('password_error');
$passwordSuccess = flash('password_success');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    if (!csrf_verify()) {
        http_response_code(400);
        exit('The form expired or could not be verified. Reload the page and try again.');
    }

    $form = $_POST['form'] ?? null;

    if ($form === 'profile') {
        $nameInput = $_POST['name'] ?? '';
        $emailInput = $_POST['email'] ?? '';
        $name = is_string($nameInput) ? trim($nameInput) : '';
        $email = is_string($emailInput) ? strtolower(trim($emailInput)) : '';
        $nameLength = preg_match_all('/./us', $name);

        if ($name === '' || $nameLength === false || $nameLength > 100) {
            flash('profile_error', 'Enter a name of 1 to 100 characters.');
        } elseif (
            strlen($email) > 254
            || filter_var($email, FILTER_VALIDATE_EMAIL) === false
        ) {
            flash('profile_error', 'Enter a valid email address.');
        } else {
            $updateProfile = db()->prepare(
                'UPDATE users SET name = :name, email = :email WHERE id = :id'
            );

            try {
                $updateProfile->execute([
                    'name' => $name,
                    'email' => $email,
                    'id' => (int) $user['id'],
                ]);
            } catch (PDOException $exception) {
                $isDuplicateKey = $exception->getCode() === '23000'
                    && (int) ($exception->errorInfo[1] ?? 0) === 1062;

                if (!$isDuplicateKey) {
                    throw $exception;
                }

                flash('profile_error', 'An account with that email address already exists.');
                redirect('profile.php');
            }

            $_SESSION['user_name'] = $name;
            $_SESSION['user_email'] = $email;
            flash('profile_success', 'Your profile has been updated.');
        }

        redirect('profile.php');
    }

    if ($form === 'password') {
        $currentPasswordInput = $_POST['current_password'] ?? '';
        $newPasswordInput = $_POST['new_password'] ?? '';
        $confirmPasswordInput = $_POST['confirm_password'] ?? '';
        $currentPassword = is_string($currentPasswordInput) ? $currentPasswordInput : '';
        $newPassword = is_string($newPasswordInput) ? $newPasswordInput : '';
        $confirmPassword = is_string($confirmPasswordInput) ? $confirmPasswordInput : '';

        $findPassword = db()->prepare('SELECT password_hash FROM users WHERE id = :id LIMIT 1');
        $findPassword->execute(['id' => (int) $user['id']]);
        $passwordHash = $findPassword->fetchColumn();

        if (
            !is_string($passwordHash)
            || !password_verify($currentPassword, $passwordHash)
        ) {
            flash('password_error', 'The current password is incorrect.');
            redirect('profile.php');
        }

        $passwordLength = preg_match_all('/./us', $newPassword);
        if (
            $passwordLength === false
            || $passwordLength < 10
            || preg_match('/\p{L}/u', $newPassword) !== 1
            || preg_match('/\p{N}/u', $newPassword) !== 1
        ) {
            flash(
                'password_error',
                'The new password must be at least 10 characters and include at least one letter and one number.'
            );
            redirect('profile.php');
        }

        if ($newPassword !== $confirmPassword) {
            flash('password_error', 'The new passwords do not match.');
            redirect('profile.php');
        }

        $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
        $updatePassword = db()->prepare(
            'UPDATE users SET password_hash = :password_hash WHERE id = :id'
        );
        $updatePassword->execute([
            'password_hash' => $newHash,
            'id' => (int) $user['id'],
        ]);

        if (!session_regenerate_id(true)) {
            throw new RuntimeException('Unable to renew the session after changing the password.');
        }

        $_SESSION['last_activity'] = time();
        flash('password_success', 'Your password has been changed.');
        redirect('profile.php');
    }

    http_response_code(400);
    exit('Invalid form submission.');
}

$user = current_user();
if ($user === null) {
    redirect('login.php');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Your profile</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<nav class="site-nav" aria-label="Main navigation">
    <a class="brand" href="dashboard.php">SWD Auth</a>
    <div class="nav-links">
        <a href="dashboard.php">Dashboard</a>
        <a href="profile.php" aria-current="page">Profile</a>
        <?php if ($user['role'] === 'admin'): ?>
            <a href="admin/users.php">Admin</a>
        <?php endif; ?>
    </div>
</nav>
<main class="auth-shell profile-shell">
    <section class="auth-card" aria-labelledby="profile-title">
        <div class="auth-heading">
            <p class="eyebrow">Account</p>
            <h1 id="profile-title">Your profile</h1>
            <p class="subtitle">Manage your account details and password.</p>
        </div>

        <?php if ($profileError !== null): ?>
            <p class="notice notice-error" role="alert"><?= e($profileError) ?></p>
        <?php endif; ?>
        <?php if ($profileSuccess !== null): ?>
            <p class="notice notice-success" role="status"><?= e($profileSuccess) ?></p>
        <?php endif; ?>

        <h2 class="section-title">Profile details</h2>
        <form method="post" action="profile.php">
            <?= csrf_field() ?>
            <input type="hidden" name="form" value="profile">

            <label for="name">Name</label>
            <input id="name" name="name" type="text" autocomplete="name" maxlength="100" required
                   value="<?= e((string) $user['name']) ?>">

            <label for="email">Email address</label>
            <input id="email" name="email" type="email" autocomplete="email" maxlength="254" required
                   value="<?= e((string) $user['email']) ?>">

            <button type="submit">Save profile</button>
        </form>

        <div class="form-divider"></div>
        <h2 class="section-title">Change password</h2>
        <?php if ($passwordError !== null): ?>
            <p class="notice notice-error" role="alert"><?= e($passwordError) ?></p>
        <?php endif; ?>
        <?php if ($passwordSuccess !== null): ?>
            <p class="notice notice-success" role="status"><?= e($passwordSuccess) ?></p>
        <?php endif; ?>

        <form method="post" action="profile.php">
            <?= csrf_field() ?>
            <input type="hidden" name="form" value="password">

            <label for="current_password">Current password</label>
            <input id="current_password" name="current_password" type="password"
                   autocomplete="current-password" required>

            <label for="new_password">New password</label>
            <input id="new_password" name="new_password" type="password"
                   autocomplete="new-password" required>
            <p class="field-hint">At least 10 characters, including a letter and a number.</p>

            <label for="confirm_password">Confirm new password</label>
            <input id="confirm_password" name="confirm_password" type="password"
                   autocomplete="new-password" required>

            <button type="submit">Change password</button>
        </form>
    </section>
</main>
</body>
</html>
