<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);



// admin.php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/campusgroups.php';


// Require login
if (empty($_SESSION['admin_id'])) {
    header('Location: login.php');
    exit;
}

// Page meta for header.php
$pageTitle   = 'CampusGroups Guest Accounts Admin';
$bodyClasses = 'cg-admin';

$errors    = [];
$success   = [];
$activeTab = $_POST['active_tab'] ?? $_GET['tab'] ?? 'new_user';

// Handle session messages
if (isset($_SESSION['success_message'])) {
    $success[] = $_SESSION['success_message'];
    unset($_SESSION['success_message']);
}
if (isset($_SESSION['error_message'])) {
    $errors[] = $_SESSION['error_message'];
    unset($_SESSION['error_message']);
}

try {
    $pdo = get_db_connection();
} catch (Exception $e) {
    $errors[] = 'Database connection failed: ' . $e->getMessage();
    $pdo = null;
}

/**
 * Generate the next NetID2 (9-digit, starting at 900000001).
 */
function generate_next_netid2(PDO $pdo): int {
    // Lock for update in case of concurrent inserts
    $stmt = $pdo->prepare("SELECT MAX(netid2) AS max_netid FROM cg_guest_users FOR UPDATE");
    $stmt->execute();
    $row = $stmt->fetch();
    $maxNetid = $row['max_netid'] ?? null;

    if ($maxNetid === null) {
        $nextNetid2 = 900000001;
    } else {
        $nextNetid2 = (int)$maxNetid + 1;
    }

    if ($nextNetid2 < 900000001 || $nextNetid2 > 999999999) {
        throw new Exception('netid2 is out of allowed range.');
    }
    return $nextNetid2;
}

/**
 * Handle POST actions
 */
if ($pdo && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    /**
     * 1) Create new guest user
     */
    if ($action === 'create_user') {
        $activeTab = 'new_user';

        $firstName   = trim($_POST['first_name'] ?? '');
        $lastName    = trim($_POST['last_name'] ?? '');
        $email       = trim($_POST['email'] ?? '');
        $association = trim($_POST['association'] ?? '');
        $sponsor     = trim($_POST['sponsor'] ?? '');
        $sponsorEmail = trim($_POST['sponsor_email'] ?? '');
        $deprovDays  = (int)($_POST['deprov_days'] ?? 0);

        if ($firstName === '')   $errors[] = 'First name is required.';
        if ($lastName === '')    $errors[] = 'Last name is required.';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Valid email is required.';
        }
        if ($association === '') $errors[] = 'Association is required.';
        if ($sponsor === '')     $errors[] = 'Sponsor name is required.';
        if (!filter_var($sponsorEmail, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Valid sponsor email is required.';
        }
        if ($deprovDays <= 0)    $errors[] = 'De-provision days must be a positive number.';


		// Enforce unique guest email
		if (!$errors) {
		    $stmt = $pdo->prepare("SELECT COUNT(*) AS cnt FROM cg_guest_users WHERE email = :email");
		    $stmt->execute([':email' => $email]);
		    $row = $stmt->fetch();
		    if ($row && (int)$row['cnt'] > 0) {
		        $errors[] = 'A guest account with this email address already exists.';
		    }
		}



        if (!$errors) {
            try {
                $pdo->beginTransaction();

                $nextNetid2 = generate_next_netid2($pdo);
                $expiresAt = (new DateTime())->modify("+{$deprovDays} days")->format('Y-m-d H:i:s');

                $stmt = $pdo->prepare("
                    INSERT INTO cg_guest_users
                      (netid2, first_name, last_name, email, association, sponsor, sponsor_email, deprov_days, expires_at)
                    VALUES
                      (:netid2, :first_name, :last_name, :email, :association, :sponsor, :sponsor_email, :deprov_days, :expires_at)
                ");
                $stmt->execute([
                    ':netid2'      => $nextNetid2,
                    ':first_name'  => $firstName,
                    ':last_name'   => $lastName,
                    ':email'       => $email,
                    ':association' => $association,
                    ':sponsor'     => $sponsor,
                    ':sponsor_email' => $sponsorEmail,
                    ':deprov_days' => $deprovDays,
                    ':expires_at'  => $expiresAt,
                ]);

                $pdo->commit();
                $_SESSION['success_message'] = "User created with NetID2: {$nextNetid2}. It will sync to CampusGroups on next run.";
				log_message(
				    "Admin created user netid2={$nextNetid2}, email={$email}",
				    'admin:' . ($_SESSION['admin_username'] ?? 'unknown')
				);
                header('Location: admin.php');
                exit;

            } catch (Exception $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                $errors[] = 'Error creating user: ' . $e->getMessage();
            }
        }
    }

    /**
     * 2) Update existing user (association, sponsor, deprov_days)
     */
    if ($action === 'update_user') {
        $activeTab = 'manage_users';

        $netid2      = (int)($_POST['netid2'] ?? 0);
        $association = trim($_POST['association'] ?? '');
        $sponsor     = trim($_POST['sponsor'] ?? '');
        $deprovDays  = (int)($_POST['deprov_days'] ?? 0);

        if ($netid2 <= 0)        $errors[] = 'Invalid NetID2.';
        if ($association === '') $errors[] = 'Association is required.';
        if ($sponsor === '')     $errors[] = 'Sponsor is required.';
        if ($deprovDays <= 0)    $errors[] = 'De-provision days must be positive.';

        if (!$errors) {
            try {
                $expiresAt = (new DateTime())->modify("+{$deprovDays} days")->format('Y-m-d H:i:s');
                $stmt = $pdo->prepare("
                    UPDATE cg_guest_users
                    SET association = :association,
                        sponsor = :sponsor,
                        deprov_days = :deprov_days,
                        expires_at = :expires_at
                    WHERE netid2 = :netid2
                ");
                $stmt->execute([
                    ':association' => $association,
                    ':sponsor'     => $sponsor,
                    ':deprov_days' => $deprovDays,
                    ':expires_at'  => $expiresAt,
                    ':netid2'      => $netid2,
                ]);

                $_SESSION['success_message'] = "User {$netid2} updated.";
				log_message(
				    "Admin updated user netid2={$netid2}",
				    'admin:' . ($_SESSION['admin_username'] ?? 'unknown')
				);
                header('Location: admin.php');
                exit;

            } catch (Exception $e) {
                $errors[] = 'Error updating user: ' . $e->getMessage();
            }
        }
    }

    /**
     * 3) Manual de-provision (immediate)
     */
    if ($action === 'manual_deprov') {
        $activeTab = 'manage_users';
        $netid2 = (int)($_POST['netid2'] ?? 0);

        if ($netid2 <= 0) {
            $errors[] = 'Invalid NetID2.';
        } else {
            $stmt = $pdo->prepare("SELECT * FROM cg_guest_users WHERE netid2 = :netid2");
            $stmt->execute([':netid2' => $netid2]);
            $user = $stmt->fetch();

            if (!$user) {
                $errors[] = "User with NetID2 {$netid2} not found.";
            } elseif (empty($user['cg_user_id'])) {
                $errors[] = "User {$netid2} has no CampusGroups ID yet; cannot de-provision via API.";
            } else {
                try {
                    $responseXml = cg_deactivate_user($user['cg_user_id']);

                    $upd = $pdo->prepare("
                        UPDATE cg_guest_users
                        SET status = 'deprovisioned',
                            last_synced_at = NOW(),
                            last_error = NULL
                        WHERE netid2 = :netid2
                    ");
                    $upd->execute([':netid2' => $netid2]);

                    $_SESSION['success_message'] = "User {$netid2} de-provisioned in CampusGroups.";
					log_message(
					    "Admin manually deprovisioned user netid2={$netid2}, cg_user_id={$user['cg_user_id']}",
					    'admin:' . ($_SESSION['admin_username'] ?? 'unknown')
					);
                    header('Location: admin.php');
                    exit;

                } catch (Exception $e) {
                    $errors[] = 'Error de-provisioning user: ' . $e->getMessage();
                }
            }
        }
    }

    /**
     * 4) Delete local user record
     */
    if ($action === 'delete_user') {
        $activeTab = 'manage_users';
        $netid2 = (int)($_POST['netid2'] ?? 0);

        if ($netid2 <= 0) {
            $errors[] = 'Invalid NetID2.';
        } else {
            try {
                $stmt = $pdo->prepare("DELETE FROM cg_guest_users WHERE netid2 = :netid2");
                $stmt->execute([':netid2' => $netid2]);
                $_SESSION['success_message'] = "User {$netid2} deleted from local database.";
				log_message(
				    "Admin deleted local record netid2={$netid2}",
				    'admin:' . ($_SESSION['admin_username'] ?? 'unknown')
				);
                header('Location: admin.php');
                exit;

            } catch (Exception $e) {
                $errors[] = 'Error deleting user: ' . $e->getMessage();
            }
        }
    }

    /**
     * 5) Create new admin
     */
    if ($action === 'create_admin') {
        $activeTab = 'admins';

        $username  = trim($_POST['admin_username'] ?? '');
        $fullName  = trim($_POST['admin_full_name'] ?? '');
        $email     = trim($_POST['admin_email'] ?? '');
        $pass1     = (string)($_POST['admin_password'] ?? '');
        $pass2     = (string)($_POST['admin_password_confirm'] ?? '');
        $isActive  = isset($_POST['admin_is_active']) ? 1 : 0;

        if ($username === '') $errors[] = 'Admin username is required.';
        if ($fullName === '') $errors[] = 'Admin full name is required.';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Admin email must be a valid email address.';
        }
        if ($pass1 === '' || $pass2 === '') {
            $errors[] = 'Admin password and confirmation are required.';
        } elseif ($pass1 !== $pass2) {
            $errors[] = 'Admin passwords do not match.';
        } elseif (strlen($pass1) < 8) {
            $errors[] = 'Admin password must be at least 8 characters.';
        }

        if (!$errors) {
            try {
                $hash = password_hash($pass1, PASSWORD_DEFAULT);

                $stmt = $pdo->prepare("
                    INSERT INTO cg_admins (username, password_hash, full_name, email, is_active)
                    VALUES (:username, :hash, :full_name, :email, :is_active)
                ");
                $stmt->execute([
                    ':username'   => $username,
                    ':hash'       => $hash,
                    ':full_name'  => $fullName,
                    ':email'      => $email,
                    ':is_active'  => $isActive,
                ]);

                $success[] = "Admin '{$username}' created.";
				log_message(
				    "Created admin user '{$username}'",
				    'admin:' . ($_SESSION['admin_username'] ?? 'unknown')
				);
				
				
				// Send email notifications to guest and sponsor
				try {
				    if (function_exists('send_guest_account_created_emails')) {
				        send_guest_account_created_emails(
				            $email,
				            $firstName,
				            $lastName,
				            $sponsor,
				            $nextNetid2,
				            $expiresAt
				        );
				        log_message(
				            "Sent guest-account-created emails to guest={$email} and sponsor={$sponsor}",
				            'system'
				        );
				    } else {
				        log_message(
				            "send_guest_account_created_emails() not defined; skipping email notifications.",
				            'system'
				        );
				    }
				} catch (Exception $e) {
				    // Log but don't block the page if email fails
				    log_message(
				        'Error sending guest-account-created emails: ' . $e->getMessage(),
				        'system'
				    );
				}			
				
				
				
				

            } catch (Exception $e) {
                $errors[] = 'Error creating admin: ' . $e->getMessage();
            }
        }
    }

    /**
     * 6) Toggle admin active/inactive
     */
    if ($action === 'toggle_admin_active') {
        $activeTab = 'admins';
        $adminId   = (int)($_POST['admin_id'] ?? 0);
        $newActive = (int)($_POST['new_is_active'] ?? 0);

        if ($adminId <= 0) {
            $errors[] = 'Invalid admin ID.';
        } else {
            // Prevent self-deactivation
            if ($newActive === 0 && isset($_SESSION['admin_id']) && $adminId == $_SESSION['admin_id']) {
                $errors[] = 'You cannot deactivate your own admin account.';
            } else {
                try {
                    // Don't deactivate the last active admin
                    if ($newActive === 0) {
                        $stmt = $pdo->query("SELECT COUNT(*) AS cnt FROM cg_admins WHERE is_active = 1");
                        $row  = $stmt->fetch();
                        if ($row && (int)$row['cnt'] <= 1) {
                            $errors[] = 'Cannot deactivate the last active admin account.';
                        }
                    }

                    if (!$errors) {
                        $stmt = $pdo->prepare("
                            UPDATE cg_admins
                            SET is_active = :is_active
                            WHERE id = :id
                        ");
                        $stmt->execute([
                            ':is_active' => $newActive,
                            ':id'        => $adminId,
                        ]);

                        $msg = $newActive ? 'reactivated' : 'deactivated';
                        $success[] = "Admin ID {$adminId} {$msg}.";
						log_message(
						    "Admin ID {$adminId} {$msg}",
						    'admin:' . ($_SESSION['admin_username'] ?? 'unknown')
						);
                        
                    }
                } catch (Exception $e) {
                    $errors[] = 'Error updating admin: ' . $e->getMessage();
                }
            }
        }
    }

    /**
     * 7) Reset admin password (by another admin)
     */
    if ($action === 'reset_admin_password') {
        $activeTab = 'admins';
        $adminId   = (int)($_POST['admin_id'] ?? 0);
        $pass1     = (string)($_POST['new_password'] ?? '');
        $pass2     = (string)($_POST['new_password_confirm'] ?? '');

        if ($adminId <= 0) {
            $errors[] = 'Invalid admin ID.';
        } elseif ($pass1 === '' || $pass2 === '') {
            $errors[] = 'New password and confirmation are required.';
        } elseif ($pass1 !== $pass2) {
            $errors[] = 'New passwords do not match.';
        } elseif (strlen($pass1) < 8) {
            $errors[] = 'New password must be at least 8 characters.';
        }

        if (!$errors) {
            try {
                $hash = password_hash($pass1, PASSWORD_DEFAULT);

                $stmt = $pdo->prepare("
                    UPDATE cg_admins
                    SET password_hash = :hash
                    WHERE id = :id
                ");
                $stmt->execute([
                    ':hash' => $hash,
                    ':id'   => $adminId,
                ]);

                $success[] = "Password reset for admin ID {$adminId}.";
				log_message(
				    "Password reset for admin ID {$adminId}",
				    'admin:' . ($_SESSION['admin_username'] ?? 'unknown')
				);

            } catch (Exception $e) {
                $errors[] = 'Error resetting admin password: ' . $e->getMessage();
            }
        }
    }

    /**
     * 8) Change my own password (self-service via top bar)
     */
    if ($action === 'change_my_password') {
        // Do not override $activeTab; keep user on their current tab.
        $adminId          = (int)($_SESSION['admin_id'] ?? 0);
        $currentPassword  = (string)($_POST['current_password'] ?? '');
        $newPassword      = (string)($_POST['new_password'] ?? '');
        $newPasswordConf  = (string)($_POST['new_password_confirm'] ?? '');

        if ($adminId <= 0) {
            $errors[] = 'Session error: admin is not logged in.';
        }

        if ($currentPassword === '' || $newPassword === '' || $newPasswordConf === '') {
            $errors[] = 'All password fields are required.';
        } elseif ($newPassword !== $newPasswordConf) {
            $errors[] = 'New password and confirmation do not match.';
        } elseif (strlen($newPassword) < 8) {
            $errors[] = 'New password must be at least 8 characters.';
        }

        if (!$errors) {
            try {
                // Fetch current admin row
                $stmt = $pdo->prepare("
                    SELECT id, username, password_hash
                    FROM cg_admins
                    WHERE id = :id AND is_active = 1
                    LIMIT 1
                ");
                $stmt->execute([':id' => $adminId]);
                $admin = $stmt->fetch();

                if (!$admin) {
                    $errors[] = 'Admin record not found or inactive.';
                } elseif (!password_verify($currentPassword, $admin['password_hash'])) {
                    $errors[] = 'Current password is incorrect.';
                } else {
                    // Update password
                    $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
                    $upd = $pdo->prepare("
                        UPDATE cg_admins
                        SET password_hash = :hash
                        WHERE id = :id
                    ");
                    $upd->execute([
                        ':hash' => $newHash,
                        ':id'   => $adminId,
                    ]);

                    $success[] = 'Your password has been updated.';
                    log_message("Admin changed own password (id={$adminId})", 'admin:' . ($_SESSION['admin_username'] ?? 'unknown'));
                }
            } catch (Exception $e) {
                $errors[] = 'Error changing password: ' . $e->getMessage();
            }
        }
    }

    /**
     * 9) Export CSV from Manage Users
     */
    if ($action === 'export_csv') {
        $activeTab = 'manage_users';

        $searchTerm     = trim($_POST['search_term']     ?? '');
        $statusFilter   = $_POST['status_filter']        ?? '';
        $dateFilterType = $_POST['date_filter_type']     ?? 'created';
        $dateFrom       = $_POST['date_from']            ?? '';
        $dateTo         = $_POST['date_to']              ?? '';

        $params = [];
        $where  = [];

        if ($searchTerm !== '') {
            $where[] = "(CAST(netid2 AS CHAR) LIKE :term OR email LIKE :term OR sponsor LIKE :term)";
            $params[':term'] = '%' . $searchTerm . '%';
        }
        if ($statusFilter !== '') {
            $where[] = "status = :status";
            $params[':status'] = $statusFilter;
        }
        if ($dateFrom !== '' || $dateTo !== '') {
            $col = ($dateFilterType === 'expires') ? 'expires_at' : 'created_at';
            if ($dateFrom !== '') {
                $where[] = "$col >= :dateFrom";
                $params[':dateFrom'] = $dateFrom . ' 00:00:00';
            }
            if ($dateTo !== '') {
                $where[] = "$col <= :dateTo";
                $params[':dateTo'] = $dateTo . ' 23:59:59';
            }
        }

        if (!$where) {
            $errors[] = 'Please run a search before exporting CSV.';
        } else {
            $sql = "SELECT * FROM cg_guest_users WHERE " . implode(' AND ', $where) . " ORDER BY created_at DESC";
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $rows = $stmt->fetchAll();

            header('Content-Type: text/csv');
            header('Content-Disposition: attachment; filename="cg_guest_users_export.csv"');

            $out = fopen('php://output', 'w');
            fputcsv($out, [
                'netid2', 'first_name', 'last_name', 'email',
                'association', 'sponsor', 'status',
                'created_at', 'expires_at', 'cg_user_id', 'notify_sent', 'notify_sent_at'
            ]);

            foreach ($rows as $r) {
                fputcsv($out, [
                    $r['netid2'],
                    $r['first_name'],
                    $r['last_name'],
                    $r['email'],
                    $r['association'],
                    $r['sponsor'],
                    $r['status'],
                    $r['created_at'],
                    $r['expires_at'],
                    $r['cg_user_id'],
                    $r['notify_sent'] ?? 0,
                    $r['notify_sent_at'] ?? '',
                ]);
            }

            fclose($out);
			log_message(
			    "Exported CSV of guest users search",
			    'admin:' . ($_SESSION['admin_username'] ?? 'unknown')
			);
            exit;
        }
    }
    /**
       * 10) Export CSV of ALL users (no filters)
       */
      if ($action === 'export_all_csv') {
          $activeTab = 'manage_users';

          try {
              $stmt = $pdo->query("
                  SELECT *
                  FROM cg_guest_users
                  ORDER BY created_at DESC
              ");
              $rows = $stmt->fetchAll();

              header('Content-Type: text/csv');
              header('Content-Disposition: attachment; filename=\"cg_guest_users_all.csv\"');

              $out = fopen('php://output', 'w');
              fputcsv($out, [
                  'netid2', 'first_name', 'last_name', 'email',
                  'association', 'sponsor', 'status',
                  'created_at', 'expires_at', 'cg_user_id', 'notify_sent', 'notify_sent_at'
              ]);

              foreach ($rows as $r) {
                  fputcsv($out, [
                      $r['netid2'],
                      $r['first_name'],
                      $r['last_name'],
                      $r['email'],
                      $r['association'],
                      $r['sponsor'],
                      $r['status'],
                      $r['created_at'],
                      $r['expires_at'],
                      $r['cg_user_id'],
                      $r['notify_sent'] ?? 0,
                      $r['notify_sent_at'] ?? '',
                  ]);
              }

              fclose($out);

              log_message(
                  "Exported CSV of ALL guest users",
                  'admin:' . ($_SESSION['admin_username'] ?? 'unknown')
              );

              exit;
          } catch (Exception $e) {
              $errors[] = 'Error exporting ALL users CSV: ' . $e->getMessage();
          }
      }
	  
	  
	  /**
	      * 11) Bulk upload users from CSV
	      */
	     if ($action === 'bulk_upload') {
	         $activeTab = 'manage_users';

	         if (!isset($_FILES['bulk_csv']) || $_FILES['bulk_csv']['error'] !== UPLOAD_ERR_OK) {
	             $errors[] = 'Please choose a valid CSV file to upload.';
	         } else {
	             $tmpName = $_FILES['bulk_csv']['tmp_name'];
	             $handle  = fopen($tmpName, 'r');

	             if (!$handle) {
	                 $errors[] = 'Unable to open uploaded CSV file.';
	             } else {
	                 $rowNumber      = 0;
	                 $createdCount   = 0;
	                 $skippedCount   = 0;
	                 $errorCount     = 0;
	                 $rowErrors      = [];

	                 // Read first line as header
	                 $header = fgetcsv($handle);
	                 $rowNumber++;

	                 if (!$header) {
	                     $errors[] = 'CSV file appears to be empty.';
	                     fclose($handle);
	                 } else {
	                     // Normalize header to lowercase
	                     $headerMap = [];
	                     foreach ($header as $idx => $colName) {
	                         $headerMap[strtolower(trim($colName))] = $idx;
	                     }

	                     $requiredCols = ['first_name','last_name','email','association','sponsor','sponsor_email','deprov_days'];
	                     $missing = [];
	                     foreach ($requiredCols as $col) {
	                         if (!array_key_exists($col, $headerMap)) {
	                             $missing[] = $col;
	                         }
	                     }

	                     if ($missing) {
	                         $errors[] = 'Missing required columns in CSV: ' . implode(', ', $missing);
	                         fclose($handle);
	                     } else {
	                         // Process rows
	                         while (($data = fgetcsv($handle)) !== false) {
	                             $rowNumber++;

	                             $firstName   = trim($data[$headerMap['first_name']] ?? '');
	                             $lastName    = trim($data[$headerMap['last_name']] ?? '');
	                             $email       = trim($data[$headerMap['email']] ?? '');
	                             $association = trim($data[$headerMap['association']] ?? '');
	                             $sponsor     = trim($data[$headerMap['sponsor']] ?? '');
	                             $sponsorEmail = trim($data[$headerMap['sponsor_email']] ?? '');
	                             $deprovDays  = (int)($data[$headerMap['deprov_days']] ?? 0);

	                             // Basic validation
	                             $thisRowErrors = [];
	                             if ($firstName === '')   $thisRowErrors[] = 'First name is required.';
	                             if ($lastName === '')    $thisRowErrors[] = 'Last name is required.';
	                             if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
	                                 $thisRowErrors[] = 'Valid email is required.';
	                             }
	                             if ($association === '') $thisRowErrors[] = 'Association is required.';
	                             if ($sponsor === '')     $thisRowErrors[] = 'Sponsor is required.';
	                             if (!filter_var($sponsorEmail, FILTER_VALIDATE_EMAIL)) {
	                                 $thisRowErrors[] = 'Valid sponsor email is required.';
	                             }
	                             if ($deprovDays <= 0)    $thisRowErrors[] = 'De-provision days must be positive.';

	                             // Enforce unique email in DB
	                             if (!$thisRowErrors) {
	                                 $stmt = $pdo->prepare("SELECT COUNT(*) AS cnt FROM cg_guest_users WHERE email = :email");
	                                 $stmt->execute([':email' => $email]);
	                                 $row = $stmt->fetch();
	                                 if ($row && (int)$row['cnt'] > 0) {
	                                     $thisRowErrors[] = 'Email already exists; skipping.';
	                                 }
	                             }

	                             if ($thisRowErrors) {
	                                 $skippedCount++;
	                                 $errorCount++;
	                                 $rowErrors[] = "Row {$rowNumber}: " . implode(' ', $thisRowErrors);
	                                 continue;
	                             }

	                             // Insert user
	                             try {
	                                 $pdo->beginTransaction();

	                                 $nextNetid2 = generate_next_netid2($pdo);
	                                 $expiresAt  = (new DateTime())->modify("+{$deprovDays} days")->format('Y-m-d H:i:s');

	                                 $stmt = $pdo->prepare("
	                                     INSERT INTO cg_guest_users
	                                       (netid2, first_name, last_name, email, association, sponsor, sponsor_email, deprov_days, expires_at)
	                                     VALUES
	                                       (:netid2, :first_name, :last_name, :email, :association, :sponsor, :sponsor_email, :deprov_days, :expires_at)
	                                 ");
	                                 $stmt->execute([
	                                     ':netid2'      => $nextNetid2,
	                                     ':first_name'  => $firstName,
	                                     ':last_name'   => $lastName,
	                                     ':email'       => $email,
	                                     ':association' => $association,
	                                     ':sponsor'     => $sponsor,
	                                     ':sponsor_email' => $sponsorEmail,
	                                     ':deprov_days' => $deprovDays,
	                                     ':expires_at'  => $expiresAt,
	                                 ]);

	                                 $pdo->commit();
	                                 $createdCount++;

	                                 log_message(
	                                     "Bulk upload: created user netid2={$nextNetid2}, email={$email}",
	                                     'admin:' . ($_SESSION['admin_username'] ?? 'unknown')
	                                 );
	                             } catch (Exception $e) {
	                                 if ($pdo->inTransaction()) {
	                                     $pdo->rollBack();
	                                 }
	                                 $skippedCount++;
	                                 $errorCount++;
	                                 $rowErrors[] = "Row {$rowNumber}: DB error: " . $e->getMessage();
	                             }
	                         } // end while rows

	                         fclose($handle);

	                         $summary = "Bulk upload complete: {$createdCount} created, {$skippedCount} skipped.";
	                         $_SESSION['success_message'] = $summary;
	                         log_message(
	                             $summary,
	                             'admin:' . ($_SESSION['admin_username'] ?? 'unknown')
	                         );

	                         if ($rowErrors) {
	                             $_SESSION['error_message'] = implode('<br>', $rowErrors);
	                         }
                         header('Location: admin.php');
                         exit;
	                     }
	                 }
	             }
	         }
	     }	  
	  
	  
	  
	  
	  
	  
	  
	  
	  
	  
	  
  } // ← keep this as the end of the POST block













/**
 * Initialize variables
 */
$searchTerm = '';
$statusFilter = '';
$dateFilterType = 'created';
$dateFrom = '';
$dateTo = '';
$searchResults = [];
$editUser = null;

/**
 * Manage Users search logic
 */
if ($pdo) {
    // Handle search form submission with redirect
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['action'])) {
        $searchParams = [];
        if (!empty($_POST['search_term'])) $searchParams['search_term'] = $_POST['search_term'];
        if (!empty($_POST['status_filter'])) $searchParams['status_filter'] = $_POST['status_filter'];
        if (!empty($_POST['date_filter_type']) && $_POST['date_filter_type'] !== 'created') $searchParams['date_filter_type'] = $_POST['date_filter_type'];
        if (!empty($_POST['date_from'])) $searchParams['date_from'] = $_POST['date_from'];
        if (!empty($_POST['date_to'])) $searchParams['date_to'] = $_POST['date_to'];
        
        $queryString = $searchParams ? '?' . http_build_query($searchParams) : '';
        header('Location: admin.php' . $queryString);
        exit;
    }
    
    // Use search data from GET parameters
    $searchTerm = trim($_GET['search_term'] ?? '');
    $statusFilter = $_GET['status_filter'] ?? '';
    $dateFilterType = $_GET['date_filter_type'] ?? 'created';
    $dateFrom = $_GET['date_from'] ?? '';
    $dateTo = $_GET['date_to'] ?? '';
    $editNetid2 = isset($_GET['edit_netid2']) ? (int)$_GET['edit_netid2'] : 0;

    $params = [];
    $where = [];

    if ($searchTerm !== '') {
        $where[] = "(CAST(netid2 AS CHAR) LIKE :term OR email LIKE :term OR sponsor LIKE :term)";
        $params[':term'] = '%' . $searchTerm . '%';
    }
    if ($statusFilter !== '') {
        $where[] = "status = :status";
        $params[':status'] = $statusFilter;
    }
    if ($dateFrom !== '' || $dateTo !== '') {
        $col = ($dateFilterType === 'expires') ? 'expires_at' : 'created_at';
        if ($dateFrom !== '') {
            $where[] = "$col >= :dateFrom";
            $params[':dateFrom'] = $dateFrom . ' 00:00:00';
        }
        if ($dateTo !== '') {
            $where[] = "$col <= :dateTo";
            $params[':dateTo'] = $dateTo . ' 23:59:59';
        }
    }

    if ($where) {
        $sql = "SELECT * FROM cg_guest_users WHERE " . implode(' AND ', $where) . " ORDER BY created_at DESC LIMIT 500";
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $searchResults = $stmt->fetchAll();
    } else {
        // Always show all users when no search criteria
        $sql = "SELECT * FROM cg_guest_users ORDER BY created_at DESC LIMIT 500";
        $stmt = $pdo->prepare($sql);
        $stmt->execute();
        $searchResults = $stmt->fetchAll();
    }

    if ($editNetid2 > 0) {
        $stmt = $pdo->prepare("SELECT * FROM cg_guest_users WHERE netid2 = :netid2");
        $stmt->execute([':netid2' => $editNetid2]);
        $editUser = $stmt->fetch();
    }
}

/**
 * Load admins list
 */
$adminList = [];
if ($pdo) {
    $stmt = $pdo->query("
        SELECT id, username, full_name, email, is_active, created_at, last_login_at
        FROM cg_admins
        ORDER BY username
    ");
    $adminList = $stmt->fetchAll();
}

/**
 * Load logs and audit trail
 */
$logLines   = [];
$auditLines = [];

$logFile = __DIR__ . '/logs/cg_sync.log';

if ($activeTab === 'logs' && file_exists($logFile)) {
    $logLines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
}

if (file_exists($logFile)) {
    $allLines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($allLines as $line) {
        if (strpos($line, '[admin:') !== false) {
            $auditLines[] = $line;
        }
    }
    $auditLines = array_reverse($auditLines);
}

require_once __DIR__ . '/header.php';
?>
  <div style="max-width:1180px; margin:1rem auto 0.5rem auto; font-size:0.9rem; color:#3f4b5b;">
    <div style="display:flex; justify-content:space-between; align-items:center; gap:1rem;">
      <div>
        Logged in as:
        <strong><?= htmlspecialchars($_SESSION['admin_full_name'] ?? $_SESSION['admin_username'] ?? 'Unknown') ?></strong>
      </div>
      <div>
        <a href="#" onclick="toggleChangePasswordPanel(); return false;">Change Password</a>
        &nbsp;|&nbsp;
        <a href="logout.php">Logout</a>
      </div>
    </div>

    <div id="changePasswordPanel" style="display:none; margin-top:0.5rem; padding:0.75rem 1rem; border-radius:6px; border:1px solid #d9dde4; background:#ffffff;">
      <form method="post" action="admin.php" style="display:flex; flex-wrap:wrap; gap:0.75rem; align-items:flex-end;">
        <input type="hidden" name="action" value="change_my_password">
        <input type="hidden" name="active_tab" value="<?= htmlspecialchars($activeTab) ?>">

        <label style="margin:0;">
          Current Password:
          <input type="password" name="current_password" required>
        </label>

        <label style="margin:0;">
          New Password:
          <input type="password" name="new_password" required>
        </label>

        <label style="margin:0;">
          Confirm New Password:
          <input type="password" name="new_password_confirm" required>
        </label>

        <button type="submit" style="margin-top:0.2rem;">Update</button>
        <button type="button" onclick="toggleChangePasswordPanel();" style="margin-top:0.2rem;">Cancel</button>
      </form>
    </div>
  </div>

  <h1>CampusGroups Guest Accounts Admin</h1>

  <div class="messages">
    <?php if ($errors): ?>
      <div class="error">
        <button onclick="this.parentElement.style.display='none'" style="float:right;background:none;border:none;font-size:18px;cursor:pointer;">&times;</button>
        <ul>
          <?php foreach ($errors as $e): ?>
            <li><?= htmlspecialchars($e) ?></li>
          <?php endforeach; ?>
        </ul>
      </div>
    <?php endif; ?>

    <?php if ($success): ?>
      <div class="success">
        <button onclick="this.parentElement.style.display='none'" style="float:right;background:none;border:none;font-size:18px;cursor:pointer;">&times;</button>
        <ul>
          <?php foreach ($success as $s): ?>
            <li><?= htmlspecialchars($s) ?></li>
          <?php endforeach; ?>
        </ul>
      </div>
    <?php endif; ?>
  </div>

  <div class="tabs">
    <div id="tab-new_user" class="tab" onclick="setActiveTab('new_user')">New User</div>
    <div id="tab-manage_users" class="tab" onclick="setActiveTab('manage_users')">Manage Users</div>
    <div id="tab-admins" class="tab" onclick="setActiveTab('admins')">Admins</div>
	<div id="tab-audit" class="tab" onclick="setActiveTab('audit')">Audit Trail</div>
    <div id="tab-logs" class="tab" onclick="setActiveTab('logs')">Logs</div>
  </div>

  <form id="tab_state_form" style="display:none;">
    <input type="hidden" name="active_tab" id="active_tab_input" value="<?= htmlspecialchars($activeTab) ?>">
  </form>

  <script>
    function setActiveTab(tabId) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      var tabEl = document.getElementById('tab-' + tabId);
      var contentEl = document.getElementById('content-' + tabId);
      if (tabEl && contentEl) {
        tabEl.classList.add('active');
        contentEl.classList.add('active');
      }
      var hidden = document.getElementById('active_tab_input');
      if (hidden) hidden.value = tabId;
    }

    function filterLogs() {
      const query = document.getElementById('logSearch').value.toLowerCase();
      const lines = document.querySelectorAll('.log-line');
      lines.forEach(line => {
        const text = line.textContent.toLowerCase();
        line.style.display = text.includes(query) ? '' : 'none';
      });
    }

    function setLogQuickFilter(token) {
      const input = document.getElementById('logSearch');
      input.value = token;
      filterLogs();
    }

    function toggleChangePasswordPanel() {
      var panel = document.getElementById('changePasswordPanel');
      if (!panel) return;
      if (panel.style.display === 'none' || panel.style.display === '') {
        panel.style.display = 'block';
      } else {
        panel.style.display = 'none';
      }
    }
  </script>

  <!-- TAB: NEW USER -->
  <div id="content-new_user" class="tab-content">
    <h2>Create New Guest User</h2>
    <form method="post" action="admin.php">
      <input type="hidden" name="active_tab" value="new_user">
      <input type="hidden" name="action" value="create_user">

      <label>
        First Name:
        <input type="text" name="first_name" required>
      </label>

      <label>
        Last Name:
        <input type="text" name="last_name" required>
      </label>

      <label>
        Email Address:
        <input type="email" name="email" required>
      </label>

      <label>
        Association with GCU:
        <select name="association" required>
          <option value="">-- Select --</option>
          <option value="Parent of student">Parent of student</option>
          <option value="Contractor">Contractor</option>
          <option value="Vendor">Vendor</option>
          <option value="Family of faculty/staff">Family of faculty/staff</option>
          <option value="Friend of student">Friend of student</option>
          <option value="Other">Other</option>
        </select>
      </label>

      <label>
        Sponsor Name (GCU community member):
        <input type="text" name="sponsor" required>
      </label>

      <label>
        Sponsor Email:
        <input type="email" name="sponsor_email" required>
      </label>

      <label>
        De-provision time (days before account expires):
        <input type="number" name="deprov_days" min="1" max="3650" required>
      </label>

      <button type="submit">Create User</button>
    </form>
  </div>

  <!-- TAB: MANAGE USERS -->
  <div id="content-manage_users" class="tab-content">
    <h2>Search / Edit / De-provision Users</h2>

    <form method="post" action="admin.php" class="search-form">
      <input type="hidden" name="active_tab" value="manage_users">

      <label>
        Search:
        <input type="text" name="search_term" value="<?= htmlspecialchars($searchTerm) ?>" style="width:200px;">
      </label>

      <label>
        Status:
        <select name="status_filter" style="width:120px;">
          <option value="">Any</option>
          <?php
            $statuses = ['pending','active','deprovisioned','failed'];
            foreach ($statuses as $st):
          ?>
            <option value="<?= $st ?>" <?= $statusFilter === $st ? 'selected' : '' ?>>
              <?= ucfirst($st) ?>
            </option>
          <?php endforeach; ?>
        </select>
      </label>

      <label>
        Date type:
        <select name="date_filter_type" style="width:100px;">
          <option value="created" <?= $dateFilterType === 'created' ? 'selected' : '' ?>>Created</option>
          <option value="expires" <?= $dateFilterType === 'expires' ? 'selected' : '' ?>>Expires</option>
        </select>
      </label>

      <label>
        From:
        <input type="date" name="date_from" value="<?= htmlspecialchars($dateFrom) ?>" style="width:150px;">
      </label>

      <label>
        To:
        <input type="date" name="date_to" value="<?= htmlspecialchars($dateTo) ?>" style="width:150px;">
      </label>

      <button type="submit">Search</button>
    </form>

  <!-- Download ALL users CSV, independent of filters -->
  <form method="post" action="admin.php" style="margin-bottom: 0.5rem;">
    <input type="hidden" name="active_tab" value="manage_users">
    <input type="hidden" name="action" value="export_all_csv">
    <button type="submit">Download CSV (All Users)</button>
  </form>




    <?php if ($searchResults): ?>
      <form method="post" action="admin.php" style="margin-top:0.25rem; margin-bottom:0.5rem;">
        <input type="hidden" name="active_tab" value="manage_users">
        <input type="hidden" name="action" value="export_csv">
        <input type="hidden" name="search_term" value="<?= htmlspecialchars($searchTerm) ?>">
        <input type="hidden" name="status_filter" value="<?= htmlspecialchars($statusFilter) ?>">
        <input type="hidden" name="date_filter_type" value="<?= htmlspecialchars($dateFilterType) ?>">
        <input type="hidden" name="date_from" value="<?= htmlspecialchars($dateFrom) ?>">
        <input type="hidden" name="date_to" value="<?= htmlspecialchars($dateTo) ?>">
        <button type="submit">Download CSV of Results</button>
      </form>
    <?php endif; ?>

    <!-- Bulk CSV Upload -->
    <form method="post" action="admin.php" enctype="multipart/form-data" style="margin-bottom: 0.5rem;">
      <input type="hidden" name="active_tab" value="manage_users">
      <input type="hidden" name="action" value="bulk_upload">
      
      Bulk Import CSV (columns: first_name, last_name, email, association, sponsor, sponsor_email, deprov_days):
      <input type="file" name="bulk_csv" accept=".csv" required>
      <button type="submit">Upload CSV</button>
    </form>

    <?php if (!$searchResults): ?>
      <p>No users found.</p>
    <?php endif; ?>

    <?php if ($searchResults): ?>
      <table>
        <thead>
          <tr>
            <th>NetID2</th>
            <th>Name</th>
            <th>Email</th>
            <th>Association</th>
            <th>Sponsor</th>
            <th>Status</th>
            <th>Expires</th>
            <th>CG User ID</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($searchResults as $u): ?>
            <tr>
              <td><?= htmlspecialchars($u['netid2']) ?></td>
              <td><?= htmlspecialchars($u['first_name'] . ' ' . $u['last_name']) ?></td>
              <td><?= htmlspecialchars($u['email']) ?></td>
              <td><?= htmlspecialchars($u['association']) ?></td>
              <td><?= htmlspecialchars($u['sponsor']) ?></td>
              <td><?= htmlspecialchars($u['status']) ?></td>
              <td><?= htmlspecialchars($u['expires_at']) ?></td>
              <td><?= htmlspecialchars($u['cg_user_id'] ?? '') ?></td>
			  
			  
			 <td>
			     <div class="action-buttons">

			         <!-- EDIT -->
			         <form method="get" action="admin.php" style="display:inline;">
			             <input type="hidden" name="tab" value="manage_users">
			             <input type="hidden" name="search_term" value="<?= htmlspecialchars($searchTerm) ?>">
			             <input type="hidden" name="status_filter" value="<?= htmlspecialchars($statusFilter) ?>">
			             <input type="hidden" name="date_filter_type" value="<?= htmlspecialchars($dateFilterType) ?>">
			             <input type="hidden" name="date_from" value="<?= htmlspecialchars($dateFrom) ?>">
			             <input type="hidden" name="date_to" value="<?= htmlspecialchars($dateTo) ?>">
			             <input type="hidden" name="edit_netid2" value="<?= (int)$u['netid2'] ?>">
			             <button type="submit">Edit</button>
			         </form>

			         <!-- DEPROV -->
			         <form method="post" action="admin.php" style="display:inline;" 
			               onsubmit="return confirm('De-provision this user now?');">
			             <input type="hidden" name="active_tab" value="manage_users">
			             <input type="hidden" name="action" value="manual_deprov">
			             <input type="hidden" name="netid2" value="<?= (int)$u['netid2'] ?>">
			             <button type="submit">De-provision</button>
			         </form>

			         <!-- DELETE -->
			         <form method="post" action="admin.php" style="display:inline;"
			               onsubmit="return confirm('Delete this user from the local database?');">
			             <input type="hidden" name="active_tab" value="manage_users">
			             <input type="hidden" name="action" value="delete_user">
			             <input type="hidden" name="netid2" value="<?= (int)$u['netid2'] ?>">
			             <button type="submit">Delete</button>
			         </form>

			     </div>
			 </td>			  
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>

    <?php if ($editUser): ?>
      <h3>Edit User: NetID2 <?= htmlspecialchars($editUser['netid2']) ?></h3>
      <form method="post" action="admin.php">
        <input type="hidden" name="active_tab" value="manage_users">
        <input type="hidden" name="action" value="update_user">
        <input type="hidden" name="netid2" value="<?= (int)$editUser['netid2'] ?>">

        <p><strong>Name:</strong> <?= htmlspecialchars($editUser['first_name'] . ' ' . $editUser['last_name']) ?><br>
           <strong>Email:</strong> <?= htmlspecialchars($editUser['email']) ?></p>

        <label>
          Association with GCU:
          <input type="text" name="association" value="<?= htmlspecialchars($editUser['association']) ?>" required>
        </label>

        <label>
          Sponsor:
          <input type="text" name="sponsor" value="<?= htmlspecialchars($editUser['sponsor']) ?>" required>
        </label>

        <label>
          De-provision time (days from now):
          <input type="number" name="deprov_days" min="1" max="3650" value="<?= (int)$editUser['deprov_days'] ?>" required>
        </label>

        <button type="submit">Save Changes</button>
      </form>
    <?php endif; ?>
  </div>

  <!-- TAB: ADMINS -->
  <div id="content-admins" class="tab-content">
    <h2>Admin Management</h2>

    <h3>Create New Admin</h3>
    <form method="post" action="admin.php">
      <input type="hidden" name="active_tab" value="admins">
      <input type="hidden" name="action" value="create_admin">

      <label>
        Username:
        <input type="text" name="admin_username" required>
      </label>

      <label>
        Full Name:
        <input type="text" name="admin_full_name" required>
      </label>

      <label>
        Email:
        <input type="email" name="admin_email" required>
      </label>

      <label>
        Password:
        <input type="password" name="admin_password" required>
      </label>

      <label>
        Confirm Password:
        <input type="password" name="admin_password_confirm" required>
      </label>

      <label>
        <input type="checkbox" name="admin_is_active" checked> Active
      </label>

      <button type="submit">Create Admin</button>
    </form>

    <hr style="margin:1.5rem 0;">

    <h3>Existing Admins</h3>

    <?php if (!$adminList): ?>
      <p>No admins found.</p>
    <?php else: ?>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Username</th>
            <th>Full Name</th>
            <th>Email</th>
            <th>Status</th>
            <th>Created</th>
            <th>Last Login</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($adminList as $a): ?>
          <tr>
            <td><?= (int)$a['id'] ?></td>
            <td><?= htmlspecialchars($a['username']) ?></td>
            <td><?= htmlspecialchars($a['full_name']) ?></td>
            <td><?= htmlspecialchars($a['email']) ?></td>
            <td><?= $a['is_active'] ? 'Active' : 'Inactive' ?></td>
            <td><?= htmlspecialchars($a['created_at']) ?></td>
            <td><?= htmlspecialchars($a['last_login_at'] ?? '') ?></td>
            <td>
              <form method="post" action="admin.php" class="inline-form" style="margin-bottom:0.25rem;">
                <input type="hidden" name="active_tab" value="admins">
                <input type="hidden" name="action" value="toggle_admin_active">
                <input type="hidden" name="admin_id" value="<?= (int)$a['id'] ?>">
                <input type="hidden" name="new_is_active" value="<?= $a['is_active'] ? 0 : 1 ?>">
                <button type="submit" onclick="return confirm('Change active status for this admin?');">
                  <?= $a['is_active'] ? 'Deactivate' : 'Reactivate' ?>
                </button>
              </form>

              <details>
                <summary style="cursor:pointer; font-size:0.85rem;">Reset Password</summary>
                <form method="post" action="admin.php" style="margin-top:0.25rem;">
                  <input type="hidden" name="active_tab" value="admins">
                  <input type="hidden" name="action" value="reset_admin_password">
                  <input type="hidden" name="admin_id" value="<?= (int)$a['id'] ?>">

                  <label style="font-size:0.8rem;">
                    New Password:
                    <input type="password" name="new_password" required>
                  </label>
                  <label style="font-size:0.8rem;">
                    Confirm:
                    <input type="password" name="new_password_confirm" required>
                  </label>
                  <button type="submit" style="margin-top:0.25rem;">Set Password</button>
                </form>
              </details>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>

  <!-- TAB: AUDIT -->
  <div id="content-audit" class="tab-content">
    <h2>Audit Trail (Admin Actions)</h2>

    <?php if (!$auditLines): ?>
      <p>No admin actions found in log.</p>
    <?php else: ?>
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Admin</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($auditLines as $line):
            $timestamp = '';
            $actor     = '';
            $message   = $line;
            if (preg_match('/^\[(.*?)\]\s+\[(.*?)\]\s+(.*)$/', $line, $m)) {
                $timestamp = $m[1];
                $actor     = $m[2];
                $message   = $m[3];
            }
        ?>
          <tr>
            <td><?= htmlspecialchars($timestamp) ?></td>
            <td><?= htmlspecialchars($actor) ?></td>
            <td><?= htmlspecialchars($message) ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>

  <!-- TAB: LOGS -->
  <div id="content-logs" class="tab-content">
    <h2>Sync Log</h2>
    <?php if (!$logLines): ?>
      <p>No log entries found.</p>
    <?php else: ?>
      <div class="log-search">
        <div style="margin-bottom:0.4rem;">
          <strong>Quick filter:</strong>
          <button type="button" onclick="setLogQuickFilter('')">All</button>
          <button type="button" onclick="setLogQuickFilter('[system]')">System</button>
          <button type="button" onclick="setLogQuickFilter('[admin:')">Admin actions</button>
        </div>
        Filter:
        <input type="text" id="logSearch" onkeyup="filterLogs()" placeholder="Type to filter log lines..." style="width:300px;">
      </div>
      <div class="log-lines" id="logContainer">
        <?php foreach ($logLines as $line): ?>
          <div class="log-line"><?= htmlspecialchars($line) ?></div>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
  </div>

  <script>
    // Clean URL and initialize the active tab on page load
    if (window.location.search) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }
    
    // Clear messages and form data on page refresh
    if (performance.navigation.type === 1) {
      document.querySelectorAll('.messages .error, .messages .success').forEach(el => el.remove());
      document.querySelectorAll('input[type="text"], input[type="date"], select').forEach(el => {
        if (el.name !== 'active_tab') el.value = '';
      });
    }
    
    setActiveTab('<?= htmlspecialchars($activeTab) ?>');
  </script>

<?php require_once __DIR__ . '/footer.php';
