<?php
// campusgroups.php
require_once __DIR__ . '/config.php';

function cg_timestamp_utc(): string {
    $dt = new DateTime('now', new DateTimeZone('UTC'));
    return $dt->format('Y-m-d\TH:i:s\Z');
}

function cg_call_api(string $soapAction, string $bodyXml): string {
    $envelope = '<?xml version="1.0" encoding="utf-8"?>'
        . '<soap:Envelope '
        . 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        . 'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
        . 'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        . '<soap:Body>'
        . $bodyXml
        . '</soap:Body>'
        . '</soap:Envelope>';

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => CG_BASE_URL,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $envelope,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: text/xml; charset=utf-8',
            'Content-Length: ' . strlen($envelope),
            'SOAPAction: "http://tempuri.org/' . $soapAction . '"'
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 30,
    ]);

    $response = curl_exec($ch);
    if ($response === false) {
        $err = curl_error($ch);
        curl_close($ch);
        throw new RuntimeException("cURL error: $err");
    }

    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode < 200 || $httpCode >= 300) {
        throw new RuntimeException("HTTP error $httpCode: $response");
    }

    return $response;
}

function cg_create_or_update_user(array $userRow): string {
    $timestamp   = cg_timestamp_utc();
    $association = htmlspecialchars($userRow['association'], ENT_XML1 | ENT_QUOTES, 'UTF-8');
    $sponsor     = htmlspecialchars($userRow['sponsor'], ENT_XML1 | ENT_QUOTES, 'UTF-8');
    $email       = htmlspecialchars($userRow['email'], ENT_XML1 | ENT_QUOTES, 'UTF-8');
    $firstName   = htmlspecialchars($userRow['first_name'], ENT_XML1 | ENT_QUOTES, 'UTF-8');
    $lastName    = htmlspecialchars($userRow['last_name'], ENT_XML1 | ENT_QUOTES, 'UTF-8');
    $netid2      = htmlspecialchars((string)$userRow['netid2'], ENT_XML1 | ENT_QUOTES, 'UTF-8');

    $cgIdPart = '';
    if (!empty($userRow['cg_user_id'])) {
        $cgId = htmlspecialchars($userRow['cg_user_id'], ENT_XML1 | ENT_QUOTES, 'UTF-8');
        $cgIdPart = "<cg_id>{$cgId}</cg_id>";
    }

    $customFieldsXml = "
        <custom_fields>
          <custom_field>
            <name>AssociationWithGCU</name>
            <value>{$association}</value>
          </custom_field>
          <custom_field>
            <name>Sponsor</name>
            <value>{$sponsor}</value>
          </custom_field>
        </custom_fields>
    ";

    $bodyXml = '
      <CreateUpdateUser xmlns="http://tempuri.org/">
        <api_key>' . htmlspecialchars(CG_API_KEY, ENT_XML1 | ENT_QUOTES, 'UTF-8') . '</api_key>
        <timestamp>' . $timestamp . '</timestamp>
        <school>' . htmlspecialchars(CG_SCHOOL, ENT_XML1 | ENT_QUOTES, 'UTF-8') . '</school>
        ' . $cgIdPart . '
        <email>' . $email . '</email>
        <first_name>' . $firstName . '</first_name>
        <last_name>' . $lastName . '</last_name>
        <netid2>' . $netid2 . '</netid2>
        ' . $customFieldsXml . '
        <account_status>1</account_status>
      </CreateUpdateUser>';

    return cg_call_api('CreateUpdateUser', $bodyXml);
}

function cg_deactivate_user(string $cgUserId): string {
    $timestamp = cg_timestamp_utc();
    $cgId      = htmlspecialchars($cgUserId, ENT_XML1 | ENT_QUOTES, 'UTF-8');

    $bodyXml = '
      <DeactivateUser xmlns="http://tempuri.org/">
        <api_key>' . htmlspecialchars(CG_API_KEY, ENT_XML1 | ENT_QUOTES, 'UTF-8') . '</api_key>
        <timestamp>' . $timestamp . '</timestamp>
        <school>' . htmlspecialchars(CG_SCHOOL, ENT_XML1 | ENT_QUOTES, 'UTF-8') . '</school>
        <cg_id>' . $cgId . '</cg_id>
      </DeactivateUser>';

    return cg_call_api('DeactivateUser', $bodyXml);
}
