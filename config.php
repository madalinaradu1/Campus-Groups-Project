<?php
// config.php

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/**
 * Helper to read env vars with a fallback.
 */
function env_or_default(string $name, $default = null) {
    $val = getenv($name);
    return $val !== false ? $val : $default;
}

// ---- Database settings (env-first, fallback to literal) ----
define('DB_HOST', env_or_default('CG_DB_HOST', 'localhost'));
define('DB_NAME', env_or_default('CG_DB_NAME', 'cg_guest'));
define('DB_USER', env_or_default('CG_DB_USER', 'root'));
define('DB_PASS', env_or_default('CG_DB_PASS', ''));

// ---- CampusGroups API settings ----
define('CG_API_KEY',  env_or_default('CG_API_KEY',   'REPLACE_ME'));
define('CG_SCHOOL',   env_or_default('CG_SCHOOL',    'gcu'));
define('CG_BASE_URL', env_or_default('CG_BASE_URL',  'https://gculife.gcu.edu/WebServices/campusgroups.asmx'));

// ---- Email / SMTP settings ----
define('MAIL_FROM_EMAIL', env_or_default('CG_MAIL_FROM_EMAIL', 'GCULife@gcu.edu'));
define('MAIL_FROM_NAME',  env_or_default('CG_MAIL_FROM_NAME',  'GCU Life Admin'));
define('MAIL_BCC_ADMIN',  env_or_default('CG_MAIL_BCC_ADMIN',  'GCULife@gcu.edu'));

define('SMTP_HOST',       env_or_default('CG_SMTP_HOST',       'smtp.office365.com'));
define('SMTP_PORT',       (int)env_or_default('CG_SMTP_PORT',  587));
define('SMTP_USERNAME',   env_or_default('CG_SMTP_USERNAME',   ''));
define('SMTP_PASSWORD',   env_or_default('CG_SMTP_PASSWORD',   ''));
define('SMTP_ENCRYPTION', env_or_default('CG_SMTP_ENCRYPTION', 'tls'));

date_default_timezone_set('America/Phoenix');

function get_db_connection(): PDO {
    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ];
    return new PDO($dsn, DB_USER, DB_PASS, $options);
}

/**
 * Log a message to logs/cg_sync.log.
 * Tags with [admin:username] if logged-in, else [system].
 */
function log_message(string $message, ?string $actor = null): void {
    if ($actor === null) {
        if (!empty($_SESSION['admin_username'])) {
            $actor = 'admin:' . $_SESSION['admin_username'];
        } else {
            $actor = 'system';
        }
    }

    $logDir = __DIR__ . '/logs';
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0775, true);
    }
    $logFile = $logDir . '/cg_sync.log';
    $line = sprintf("[%s] [%s] %s\n", date('Y-m-d H:i:s'), $actor, $message);
    @file_put_contents($logFile, $line, FILE_APPEND);
}
