<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

$errors = [];
$name = '';
$email = '';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    if (!csrf_verify()) {
        http_response_code(400);
        exit('The form expired or could not be verified. Reload the page and try again.');
    }

    $nameInput = $_POST['name'] ?? '';
    $emailInput = $_POST['email'] ?? '';
    $passwordInput = $_POST['password'] ?? '';
    $confirmInput = $_POST['confirm_password'] ?? '';

    $name = is_string($nameInput) ? trim($nameInput) : '';
    $email = is_string($emailInput) ? strtolower(trim($emailInput)) : '';
    $password = is_string($passwordInput) ? $passwordInput : '';
    $confirmPassword = is_string($confirmInput) ? $confirmInput : '';

    $nameLength = preg_match_all('/./us', $name);
    if ($name === '' || $nameLength === false || $nameLength > 100) {
        $errors[] = 'Enter a name of 1 to 100 characters.';
    }

    if (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        $errors[] = 'Enter a valid email address.';
    }

    $passwordLength = preg_match_all('/./us', $password);
    if (
        $passwordLength === false
        || $passwordLength < 10
        || preg_match('/\p{L}/u', $password) !== 1
        || preg_match('/\p{N}/u', $password) !== 1
    ) {
        $errors[] = 'Password must be at least 10 characters and include at least one letter and one number.';
    }

    if ($password !== $confirmPassword) {
        $errors[] = 'The passwords do not match.';
    }

    if ($errors === []) {
        $checkEmail = db()->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
        $checkEmail->execute(['email' => $email]);

        if ($checkEmail->fetchColumn() !== false) {
            $errors[] = 'An account with that email address already exists.';
        } else {
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            $insertUser = db()->prepare(
                'INSERT INTO users (name, email, password_hash, `role`, last_login_at) '
                . 'VALUES (:name, :email, :password_hash, \'user\', CURRENT_TIMESTAMP)'
            );

            try {
                $insertUser->execute([
                    'name' => $name,
                    'email' => $email,
                    'password_hash' => $passwordHash,
                ]);
            } catch (PDOException $exception) {
                $isDuplicateKey = $exception->getCode() === '23000'
                    && (int) ($exception->errorInfo[1] ?? 0) === 1062;

                if (!$isDuplicateKey) {
                    throw $exception;
                }

                $errors[] = 'An account with that email address already exists.';
            }

            if ($errors === []) {
                if (!session_regenerate_id(true)) {
                    throw new RuntimeException('Unable to renew the session after registration.');
                }

                $_SESSION['user_id'] = (int) db()->lastInsertId();
                $_SESSION['user_name'] = $name;
                $_SESSION['user_email'] = $email;
                $_SESSION['user_role'] = 'user';
                $_SESSION['last_activity'] = time();
                unset($_SESSION['_old']);

                redirect('dashboard.php');
            }
        }
    }

    if ($errors !== []) {
        $_SESSION['_old'] = [
            'name' => $name,
            'email' => $email,
        ];
        flash('register_error', implode(' ', $errors));
        redirect('register.php');
    }
}

$name = old('name');
$email = old('email');
$errorMessage = flash('register_error');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Create account</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-shell">
    <section class="auth-card" aria-labelledby="register-title">
        <div class="auth-heading">
            <p class="eyebrow">SWD Auth</p>
            <h1 id="register-title">Create your account</h1>
            <p class="subtitle">Get started by filling in your details below.</p>
        </div>

        <?php if ($errorMessage !== null): ?>
            <p class="notice notice-error" role="alert"><?= e($errorMessage) ?></p>
        <?php endif; ?>

        <form method="post" action="register.php">
            <?= csrf_field() ?>

            <label for="name">Name</label>
            <input id="name" name="name" type="text" autocomplete="name" maxlength="100" required
                   value="<?= e($name) ?>">

            <label for="email">Email address</label>
            <input id="email" name="email" type="email" autocomplete="email" maxlength="254" required
                   value="<?= e($email) ?>">

            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="new-password" required>
            <p class="field-hint">At least 10 characters, including a letter and a number.</p>

            <label for="confirm_password">Confirm password</label>
            <input id="confirm_password" name="confirm_password" type="password"
                   autocomplete="new-password" required>

            <button type="submit">Create account</button>
        </form>

        <p class="auth-footer">Already have an account? <a href="login.php">Sign in</a></p>
    </section>
</main>
</body>
</html>
