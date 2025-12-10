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
  <!-- Bootstrap 5 -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <!-- AdminLTE -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@3.2/dist/css/adminlte.min.css">
  <!-- Font Awesome -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" crossorigin="anonymous">
  <!-- Font Awesome Fallback -->
  <link rel="stylesheet" href="https://use.fontawesome.com/releases/v6.4.0/css/all.css" crossorigin="anonymous">
  <!-- Custom CSS -->
  <link rel="stylesheet" href="/cg-guest-project/css/CT.css">
  <link rel="stylesheet" href="/cg-guest-project/css/admin.css">
  <link rel="stylesheet" href="/cg-guest-project/css/mainStyle.css">
  
</head>
<body class="hold-transition sidebar-mini layout-fixed <?= htmlspecialchars($bodyClasses) ?>">
