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
  <div class="login-page">
    <div class="login-box">
      <div class="login-logo">
        <b>GCU Life</b> Admin
      </div>
      <div class="card">
        <div class="card-body login-card-body">
          <p class="login-box-msg">CampusGroups Guest Account Console</p>

          <?php if ($errors): ?>
            <div class="alert alert-danger">
              <?php foreach ($errors as $e): ?>
                <div><?= htmlspecialchars($e) ?></div>
              <?php endforeach; ?>
            </div>
          <?php endif; ?>

          <form method="post" action="login.php">
            <div class="input-group mb-3">
              <input type="text" class="form-control" name="username" placeholder="Username" required autofocus>
              <div class="input-group-append">
                <div class="input-group-text">
                  <span class="fas fa-user"></span>
                </div>
              </div>
            </div>
            <div class="input-group mb-3">
              <input type="password" class="form-control" name="password" placeholder="Password" required>
              <div class="input-group-append">
                <div class="input-group-text">
                  <span class="fas fa-lock"></span>
                </div>
              </div>
            </div>
            <div class="row">
              <div class="col-12">
                <button type="submit" class="btn btn-primary btn-block">Sign In</button>
              </div>
            </div>
          </form>

          <p class="mt-3 mb-1 text-muted text-center">
            <small>Internal use only. Access restricted to authorized GCU Life administrators.</small>
          </p>
        </div>
      </div>
    </div>
  </div>
<?php require_once __DIR__ . '/footer.php';
