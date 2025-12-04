<?php
// header.php
require_once __DIR__ . '/config.php';

// Allow pages to override these before including header.php
$bodyClasses = $bodyClasses ?? 'cg-admin';
$pageTitle   = $pageTitle   ?? 'GCU Life Admin';
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title><?= htmlspecialchars($pageTitle) ?></title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="/cg-guest-project/css/CT.css">
  <link rel="stylesheet" href="/cg-guest-project/css/admin.css">
  <link rel="stylesheet" href="/cg-guest-project/css/mainStyle.css">
  
</head>
<body class="<?= htmlspecialchars($bodyClasses) ?>">
