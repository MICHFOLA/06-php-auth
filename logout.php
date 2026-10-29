<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Method not allowed.');
}

if (!csrf_verify()) {
    http_response_code(400);
    exit('The form expired or could not be verified. Reload the page and try again.');
}

end_session_with_flash('You have been logged out.');
