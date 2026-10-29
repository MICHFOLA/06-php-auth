<?php
declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';

$admin = require_role('admin');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    if (!csrf_verify()) {
        http_response_code(400);
        exit('The form expired or could not be verified. Reload the page and try again.');
    }

    $targetId = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
    $targetRole = $_POST['role'] ?? null;

    if (!is_int($targetId) || $targetId < 1 || !in_array($targetRole, ['user', 'admin'], true)) {
        flash('admin_error', 'Choose a valid user and role.');
        redirect('users.php');
    }

    if ($targetId === (int) $admin['id'] && $targetRole !== 'admin') {
        flash('admin_error', 'You cannot remove your own admin role.');
        redirect('users.php');
    }

    $existingUser = db()->prepare('SELECT id FROM users WHERE id = :id LIMIT 1');
    $existingUser->execute(['id' => $targetId]);
    if ($existingUser->fetchColumn() === false) {
        flash('admin_error', 'That user could not be found.');
        redirect('users.php');
    }

    $updateRole = db()->prepare('UPDATE users SET `role` = :role WHERE id = :id');
    $updateRole->execute([
        'role' => $targetRole,
        'id' => $targetId,
    ]);

    flash('admin_success', 'User role updated.');
    redirect('users.php');
}

$users = db()->query(
    'SELECT id, name, email, `role`, created_at, last_login_at FROM users ORDER BY id ASC'
)->fetchAll();
$errorMessage = flash('admin_error');
$successMessage = flash('admin_success');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Manage users</title>
    <link rel="stylesheet" href="../assets/auth.css">
</head>
<body>
<nav class="site-nav" aria-label="Main navigation">
    <a class="brand" href="../dashboard.php">SWD Auth</a>
    <div class="nav-links">
        <a href="../dashboard.php">Dashboard</a>
        <?php if ($admin['role'] === 'admin'): ?>
            <a href="users.php" aria-current="page">Admin</a>
        <?php endif; ?>
    </div>
</nav>
<main class="admin-shell">
    <header class="admin-heading">
        <p class="eyebrow">Administration</p>
        <h1>Manage users</h1>
        <p class="subtitle">Review accounts and manage administrator access.</p>
    </header>

    <?php if ($errorMessage !== null): ?>
        <p class="notice notice-error" role="alert"><?= e($errorMessage) ?></p>
    <?php endif; ?>
    <?php if ($successMessage !== null): ?>
        <p class="notice notice-success" role="status"><?= e($successMessage) ?></p>
    <?php endif; ?>

    <div class="table-wrap">
        <table class="user-table">
            <thead>
            <tr>
                <th scope="col">Name</th>
                <th scope="col">Email</th>
                <th scope="col">Role</th>
                <th scope="col">Created</th>
                <th scope="col">Last login</th>
                <th scope="col">Update role</th>
            </tr>
            </thead>
            <tbody>
            <?php foreach ($users as $listedUser): ?>
                <tr>
                    <td><?= e((string) $listedUser['name']) ?></td>
                    <td><?= e((string) $listedUser['email']) ?></td>
                    <td><?= e((string) $listedUser['role']) ?></td>
                    <td><?= e((string) $listedUser['created_at']) ?></td>
                    <td><?= e($listedUser['last_login_at'] === null
                        ? 'Never'
                        : (string) $listedUser['last_login_at']) ?></td>
                    <td>
                        <form class="role-form" method="post" action="users.php">
                            <?= csrf_field() ?>
                            <input type="hidden" name="user_id" value="<?= (int) $listedUser['id'] ?>">
                            <label class="visually-hidden" for="role-<?= (int) $listedUser['id'] ?>">
                                Role for <?= e((string) $listedUser['name']) ?>
                            </label>
                            <select id="role-<?= (int) $listedUser['id'] ?>" name="role">
                                <option value="user" <?= $listedUser['role'] === 'user' ? 'selected' : '' ?>>
                                    User
                                </option>
                                <option value="admin" <?= $listedUser['role'] === 'admin' ? 'selected' : '' ?>>
                                    Admin
                                </option>
                            </select>
                            <button type="submit">Save</button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</main>
</body>
</html>
