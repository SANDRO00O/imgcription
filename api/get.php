<?php
// api/get.php
require_once __DIR__ . '/helpers.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_resp(['success' => false, 'message' => 'Method not allowed'], 405);
}

check_origin_or_die();

// Rate limit
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if (is_rate_limited($ip)) {
    json_resp(['success' => false, 'message' => 'Too many requests'], 429);
}

$raw = file_get_contents('php://input');
$data = json_decode($raw, true);
if (!is_array($data)) {
    json_resp(['success' => false, 'message' => 'Invalid request'], 400);
}

// Expect token only. Password is used client-side for decryption.
$token = isset($data['token']) ? trim($data['token']) : '';
if ($token === '' || !preg_match('/^[0-9a-fA-F]{48,128}$/', $token)) {
    json_resp(['success' => false, 'message' => 'Invalid token'], 400);
}

try {
    require_once __DIR__ . '/config.php';
    $stmt = $pdo->prepare("SELECT cipher_blob, iv, salt FROM images_secure WHERE token = :token LIMIT 1");
    $stmt->execute([':token' => $token]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        // لا تفصح إن كان غير موجود أو كلمة المرور خاطئة — رسالة عامة
        json_resp(['success' => false, 'message' => 'Not found or access denied'], 404);
    }

    $cipher_b64 = base64_encode($row['cipher_blob']);
    $iv_b64 = base64_encode($row['iv']);
    $salt_b64 = base64_encode($row['salt']);

    json_resp([
        'success' => true,
        'ciphertext' => $cipher_b64,
        'iv' => $iv_b64,
        'salt' => $salt_b64
    ], 200);
} catch (PDOException $e) {
    json_resp(['success' => false, 'message' => 'Server error'], 500);
}
?>