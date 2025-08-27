<?php
// api/upload.php
require_once __DIR__ . '/helpers.php';

// Only POST allowed
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_resp(['success' => false, 'message' => 'Method not allowed'], 405);
}

// Origin check
check_origin_or_die();

// Rate limit
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if (is_rate_limited($ip)) {
    json_resp(['success' => false, 'message' => 'Too many requests'], 429);
}

// Read JSON
$raw = file_get_contents('php://input');
$data = json_decode($raw, true);
if (!is_array($data)) {
    json_resp(['success' => false, 'message' => 'Invalid request'], 400);
}

// Expected fields: token, ciphertext (base64), iv (base64), salt (base64), size (int)
$token = isset($data['token']) ? trim($data['token']) : '';
$cipher_b64 = isset($data['ciphertext']) ? $data['ciphertext'] : '';
$iv_b64 = isset($data['iv']) ? $data['iv'] : '';
$salt_b64 = isset($data['salt']) ? $data['salt'] : '';
$size = isset($data['size']) ? intval($data['size']) : 0;

if ($token === '' || $cipher_b64 === '' || $iv_b64 === '' || $salt_b64 === '' || $size <= 0) {
    json_resp(['success' => false, 'message' => 'Missing fields'], 400);
}

// Validate token format (hex)
if (!preg_match('/^[0-9a-fA-F]{48,128}$/', $token)) {
    json_resp(['success' => false, 'message' => 'Invalid token'], 400);
}

// decode base64
$cipher = base64_decode($cipher_b64, true);
$iv = base64_decode($iv_b64, true);
$salt = base64_decode($salt_b64, true);
if ($cipher === false || $iv === false || $salt === false) {
    json_resp(['success' => false, 'message' => 'Invalid data encoding'], 400);
}

// server-side size check (ciphertext)
if (strlen($cipher) > MAX_CIPHER_BYTES) {
    json_resp(['success' => false, 'message' => 'File too large'], 413);
}

// Insert into DB
try {
    require_once __DIR__ . '/config.php';
    $stmt = $pdo->prepare("INSERT INTO images_secure (token, cipher_blob, iv, salt, size) VALUES (:token, :cipher, :iv, :salt, :size)");
    $stmt->bindParam(':token', $token);
    $stmt->bindParam(':cipher', $cipher, PDO::PARAM_LOB);
    $stmt->bindParam(':iv', $iv, PDO::PARAM_LOB);
    $stmt->bindParam(':salt', $salt, PDO::PARAM_LOB);
    $stmt->bindParam(':size', $size, PDO::PARAM_INT);
    $stmt->execute();
    json_resp(['success' => true, 'message' => 'Stored securely', 'token' => $token], 201);
} catch (PDOException $e) {
    // If duplicate token (نادرة جداً) أخفِ التفاصيل
    if ($e->errorInfo[1] == 1062) {
        json_resp(['success' => false, 'message' => 'Conflict, retry upload'], 409);
    } else {
        // سجل الخطأ في لوج داخلي إن أردت (ولا تعرضه للمستخدم)
        json_resp(['success' => false, 'message' => 'Server error'], 500);
    }
}
?>