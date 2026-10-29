<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/src/db.php';

$email = $argv[1] ?? '';
if (!is_string($email) || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    fwrite(STDERR, "Usage: php promote-admin.php user@example.com\n");
    exit(2);
}

$email = strtolower(trim($email));
$findUser = db()->prepare('SELECT id, `role` FROM users WHERE email = :email LIMIT 1');
$findUser->execute(['email' => $email]);
$user = $findUser->fetch();

if (!is_array($user)) {
    fwrite(STDERR, "No user found with that email address.\n");
    exit(1);
}

if ($user['role'] !== 'admin') {
    $promoteUser = db()->prepare('UPDATE users SET `role` = \'admin\' WHERE id = :id');
    $promoteUser->execute(['id' => (int) $user['id']]);
}

fwrite(STDOUT, "Admin access granted to {$email}.\n");
