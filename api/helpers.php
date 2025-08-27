<?php
// api/helpers.php
require_once __DIR__ . '/config.php';

// Security headers for API responses
function send_security_headers(){
    // HSTS: تأكد من تفعيل HTTPS قبل تفعيل هذا السطر في الإنتاج
    header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    // لا تضيف CSP هنا لأن الموقع ثابت؛ لكن نضع قاعدة عامة
    header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none';");
}

// Origin check (simple)
function check_origin_or_die(){
    if (!isset($_SERVER['HTTP_ORIGIN']) && !isset($_SERVER['HTTP_REFERER'])) {
        // قد يكون عميل غير متصفّح (مثلاً curl) — نسمح جزئياً، لكن يمكنك تشديده
        return true;
    }
    $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
    if (!$origin && isset($_SERVER['HTTP_REFERER'])) {
        $ref = parse_url($_SERVER['HTTP_REFERER']);
        if ($ref && isset($ref['scheme']) && isset($ref['host'])) {
            $origin = $ref['scheme'] . '://' . $ref['host'];
        }
    }
    if ($origin) {
        global $ALLOWED_ORIGINS;
        if (in_array($origin, ALLOWED_ORIGINS)) {
            header("Access-Control-Allow-Origin: $origin");
            header('Access-Control-Allow-Credentials: true');
            header('Vary: Origin');
            return true;
        } else {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Forbidden']);
            exit;
        }
    }
    return true;
}

// Simple filesystem-based rate limiting per IP (slim, for demo)
// stores timestamps in a file per IP; not perfect but works without Redis
function is_rate_limited($ip){
    $dir = RATE_LIMIT_DIR;
    $key = 'rl_' . preg_replace('/[^a-z0-9\.\-_]/i','_', $ip);
    $file = $dir . '/' . $key;
    $now = time();
    $window = RATE_LIMIT_WINDOW;
    $max = RATE_LIMIT_MAX;

    // read existing or create
    $timestamps = [];
    if (file_exists($file)) {
        $data = @file_get_contents($file);
        if ($data !== false) {
            $timestamps = explode(',', trim($data));
            $timestamps = array_filter($timestamps, function($t) use ($now, $window){
                return ($t + $window) >= $now;
            });
        }
    }

    $timestamps[] = $now;
    // write back
    @file_put_contents($file, implode(',', $timestamps), LOCK_EX);

    if (count($timestamps) > $max) {
        return true;
    }
    return false;
}

// Generic JSON response helper
function json_resp($arr, $code = 200){
    send_security_headers();
    header('Content-Type: application/json; charset=utf-8');
    http_response_code($code);
    echo json_encode($arr);
    exit;
}
?>