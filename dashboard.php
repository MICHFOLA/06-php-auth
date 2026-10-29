<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

$user = require_login();
$lastLogin = $user['last_login_at'] === null
    ? 'Not available'
    : (string) $user['last_login_at'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<nav class="site-nav" aria-label="Main navigation">
    <a class="brand" href="dashboard.php">SWD Auth</a>
    <div class="nav-links">
        <a href="dashboard.php">Dashboard</a>
        <?php if ($user['role'] === 'admin'): ?>
            <a href="admin/users.php">Admin</a>
        <?php endif; ?>
    </div>
</nav>
<main class="auth-shell">
    <section class="auth-card" aria-labelledby="dashboard-title">
        <div class="auth-heading">
            <p class="eyebrow">SWD Auth</p>
            <h1 id="dashboard-title">Welcome, <?= e((string) $user['name']) ?></h1>
            <p class="subtitle">You are signed in to your account.</p>
        </div>

        <dl class="account-details">
            <div>
                <dt>Email</dt>
                <dd><?= e((string) $user['email']) ?></dd>
            </div>
            <div>
                <dt>Role</dt>
                <dd><?= e((string) $user['role']) ?></dd>
            </div>
            <div>
                <dt>Account created</dt>
                <dd><?= e((string) $user['created_at']) ?></dd>
            </div>
            <div>
                <dt>Last login</dt>
                <dd><?= e($lastLogin) ?></dd>
            </div>
        </dl>

        <form method="post" action="logout.php">
            <?= csrf_field() ?>
            <button type="submit" class="button-secondary">Log out</button>
        </form>
    </section>
</main>
</body>
</html>
