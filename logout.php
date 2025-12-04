<?php
// logout.php
require_once __DIR__ . '/config.php';

if (!empty($_SESSION['admin_username'])) {
    log_message("Admin logged out: {$_SESSION['admin_username']}");
}

$_SESSION = [];
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}
session_destroy();

header('Location: login.php');
exit;
