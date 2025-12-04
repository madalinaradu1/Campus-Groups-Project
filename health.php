<?php
// health.php
require_once __DIR__ . '/config.php';

header('Content-Type: application/json');

$status = [
    'status'    => 'ok',
    'db'        => 'unknown',
    'timestamp' => date('c'),
];

try {
    $pdo = get_db_connection();
    $stmt = $pdo->query('SELECT 1');
    $stmt->fetchColumn();
    $status['db'] = 'ok';
} catch (Exception $e) {
    $status['status'] = 'degraded';
    $status['db']     = 'error';
    $status['error']  = 'DB connection failed';
}

echo json_encode($status);
