<?php
// email.php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

function send_expiry_notice(array $user): bool
{
    $mail = new PHPMailer(true);

    try {
        $mail->isSMTP();
        $mail->Host       = SMTP_HOST;
        $mail->Port       = SMTP_PORT;
        $mail->SMTPAuth   = true;
        $mail->Username   = SMTP_USERNAME;
        $mail->Password   = SMTP_PASSWORD;
        $mail->SMTPSecure = SMTP_ENCRYPTION;

        $mail->setFrom(MAIL_FROM_EMAIL, MAIL_FROM_NAME);
        $mail->addAddress($user['email'], trim($user['first_name'] . ' ' . $user['last_name']));

        if (MAIL_BCC_ADMIN) {
            $mail->addBCC(MAIL_BCC_ADMIN);
        }

        $mail->isHTML(true);
        $mail->Subject = 'Reminder: Your CampusGroups guest account will expire in 7 days';

        $expiresAt = new DateTime($user['expires_at']);
        $expiresStr = $expiresAt->format('F j, Y');

        $firstName  = htmlspecialchars($user['first_name'], ENT_QUOTES, 'UTF-8');
        $netid2     = htmlspecialchars((string)$user['netid2'], ENT_QUOTES, 'UTF-8');
        $sponsor    = htmlspecialchars($user['sponsor'] ?? '', ENT_QUOTES, 'UTF-8');

        $bodyHtml = "
            <p>Hi {$firstName},</p>
            <p>This is a friendly reminder that your CampusGroups guest account associated with Grand Canyon University will expire in <strong>7 days</strong>.</p>
            <p><strong>Account details:</strong><br>
            Guest NetID2: <code>{$netid2}</code><br>
            Email: {$user['email']}<br>
            Scheduled expiration date: {$expiresStr}</p>
        ";

        if ($sponsor !== '') {
            $bodyHtml .= "
                <p>If you believe you still need access, please contact your GCU sponsor:<br>
                <strong>{$sponsor}</strong></p>
            ";
        }

        $bodyHtml .= "
            <p>After the expiration date, your CampusGroups guest access will be de-provisioned automatically.</p>
            <p>Thank you,<br>
            GCU Life Admin</p>
        ";

        $mail->Body    = $bodyHtml;
        $mail->AltBody = strip_tags(
            "Hi {$firstName},\n\n" .
            "This is a friendly reminder that your CampusGroups guest account associated with Grand Canyon University will expire in 7 days.\n\n" .
            "Account details:\n" .
            "Guest NetID2: {$netid2}\n" .
            "Email: {$user['email']}\n" .
            "Scheduled expiration date: {$expiresStr}\n\n" .
            ($sponsor !== '' ? "If you still need access, please contact your GCU sponsor: {$sponsor}\n\n" : "") .
            "After the expiration date, your CampusGroups guest access will be de-provisioned automatically.\n\n" .
            "Thank you,\nGCU Life Admin"
        );

        $mail->send();
        return true;

    } catch (Exception $e) {
        log_message('Error sending expiry notice to ' . $user['email'] . ': ' . $e->getMessage());
        return false;
    }
}




/**
 * Send notification emails when a guest account is created:
 *  - to the guest
 *  - to the sponsor (if we can detect an email address in the sponsor field)
 */
function send_guest_account_created_emails(
    string $guestEmail,
    string $guestFirstName,
    string $guestLastName,
    string $sponsorField,
    int $netid2,
    string $expiresAt
): void {
    // Try to extract an email from the sponsor field (it might be just a name)
    $sponsorEmail = null;
    if (filter_var($sponsorField, FILTER_VALIDATE_EMAIL)) {
        $sponsorEmail = $sponsorField;
    } else {
        // If the sponsor field contains a name + email in parentheses, you could try to parse it here.
        // For now, we only send sponsor notification when it's a clean email address.
    }

    // Format some friendly strings
    $guestName   = trim($guestFirstName . ' ' . $guestLastName);
    $expiresDate = $expiresAt !== '' ? date('F j, Y', strtotime($expiresAt)) : 'a future date';

    // 1) Email to the guest
    try {
        $mail = new PHPMailer(true);

        // TODO: fill in your SMTP settings here
        // $mail->isSMTP();
        // $mail->Host       = 'smtp.example.com';
        // $mail->SMTPAuth   = true;
        // $mail->Username   = '...';
        // $mail->Password   = '...';
        // $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        // $mail->Port       = 587;

        $mail->setFrom('GCULife@gcu.edu', 'GCU Life Admin');
        $mail->addAddress($guestEmail, $guestName);

        $mail->Subject = 'Your CampusGroups guest account has been created';
        $mail->isHTML(true);

        $bodyGuest = "
            <p>Hello " . htmlspecialchars($guestName) . ",</p>
            <p>A CampusGroups guest account has been created for you so you can participate in GCU Life events and activities.</p>
            <p><strong>NetID2:</strong> {$netid2}<br>
               <strong>Expires on or after:</strong> {$expiresDate}</p>
            <p>Your sponsor at GCU is: " . htmlspecialchars($sponsorField) . ".</p>
            <p>If you have any questions about this account, please contact your sponsor or reply to this email.</p>
            <p>Thank you,<br>GCU Life Admin</p>
        ";

        $mail->Body = $bodyGuest;
        $mail->AltBody = "Hello {$guestName},\n\n"
            . "A CampusGroups guest account has been created for you.\n\n"
            . "NetID2: {$netid2}\n"
            . "Expires on or after: {$expiresDate}\n"
            . "Sponsor: {$sponsorField}\n\n"
            . "Thank you,\nGCU Life Admin";

        $mail->send();
    } catch (Exception $e) {
        // Optional: log but don't break the page
        if (function_exists('log_message')) {
            log_message(
                'Error sending guest account email to guest: ' . $e->getMessage(),
                'system'
            );
        }
    }

    // 2) Email to the sponsor (if we have an email address)
    if ($sponsorEmail) {
        try {
            $mail = new PHPMailer(true);

            // TODO: same SMTP config as above
            // $mail->isSMTP();
            // ...

            $mail->setFrom('GCULife@gcu.edu', 'GCU Life Admin');
            $mail->addAddress($sponsorEmail);

            $mail->Subject = 'CampusGroups guest account created for your guest';
            $mail->isHTML(true);

            $bodySponsor = "
                <p>Hello,</p>
                <p>A CampusGroups guest account has just been created for your guest:</p>
                <p><strong>Guest:</strong> " . htmlspecialchars($guestName) . "<br>
                   <strong>Guest email:</strong> " . htmlspecialchars($guestEmail) . "<br>
                   <strong>NetID2:</strong> {$netid2}<br>
                   <strong>Expires on or after:</strong> {$expiresDate}</p>
                <p>You are listed as this guest's sponsor with the following value:<br>
                   <code>" . htmlspecialchars($sponsorField) . "</code></p>
                <p>If this is unexpected or incorrect, please contact GCU Life Admin.</p>
                <p>Thank you,<br>GCU Life Admin</p>
            ";

            $mail->Body = $bodySponsor;
            $mail->AltBody = "A CampusGroups guest account has been created.\n\n"
                . "Guest: {$guestName}\n"
                . "Guest email: {$guestEmail}\n"
                . "NetID2: {$netid2}\n"
                . "Expires on or after: {$expiresDate}\n"
                . "Sponsor field: {$sponsorField}\n\n"
                . "If this is unexpected, please contact GCU Life Admin.";

            $mail->send();
        } catch (Exception $e) {
            if (function_exists('log_message')) {
                log_message(
                    'Error sending guest account email to sponsor: ' . $e->getMessage(),
                    'system'
                );
            }
        }
    }
}
