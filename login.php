<?php
// login.php
require_once __DIR__ . '/config.php';

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = (string)($_POST['password'] ?? '');

    if ($username === '' || $password === '') {
        $errors[] = 'Username and password are required.';
    } else {
        try {
            $pdo = get_db_connection();
            $stmt = $pdo->prepare("
                SELECT *
                FROM cg_admins
                WHERE username = :username AND is_active = 1
                LIMIT 1
            ");
            $stmt->execute([':username' => $username]);
            $admin = $stmt->fetch();

            if ($admin && password_verify($password, $admin['password_hash'])) {
                $_SESSION['admin_id']        = $admin['id'];
                $_SESSION['admin_username']  = $admin['username'];
                $_SESSION['admin_full_name'] = $admin['full_name'];

                $upd = $pdo->prepare("UPDATE cg_admins SET last_login_at = NOW() WHERE id = :id");
                $upd->execute([':id' => $admin['id']]);

                log_message("Admin logged in: {$admin['username']}", 'admin:' . $admin['username']);

                header('Location: admin.php');
                exit;
            } else {
                $errors[] = 'Invalid username or password.';
                log_message("Failed admin login attempt for username='{$username}'");
            }
        } catch (Exception $e) {
            $errors[] = 'Login error: ' . $e->getMessage();
        }
    }
}

$pageTitle   = 'GCU Life Admin Login';
$bodyClasses = 'cg-admin login-page';

require_once __DIR__ . '/header.php';
?>
  <div class="login-shell">
    <div class="login-header">
      <div class="login-title">GCU Life Admin</div>
      <div class="login-subtitle">CampusGroups Guest Account Console</div>
    </div>

    <div class="login-card">
      <?php if ($errors): ?>
        <div class="login-errors">
          <ul>
            <?php foreach ($errors as $e): ?>
              <li><?= htmlspecialchars($e) ?></li>
            <?php endforeach; ?>
          </ul>
        </div>
      <?php endif; ?>

      <form method="post" action="login.php">
        <label>
          Username
          <input type="text" name="username" required autofocus>
        </label>

        <label>
          Password
          <input type="password" name="password" required>
        </label>

        <button type="submit">Sign In</button>
      </form>

      <div class="login-footnote">
        Internal use only. Access restricted to authorized GCU Life administrators.
      </div>
    </div>
  </div>
<?php require_once __DIR__ . '/footer.php';
