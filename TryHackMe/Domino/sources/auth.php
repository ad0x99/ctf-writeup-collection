<?php
require_once __DIR__ . '/config.php';

function get_session() {
    if (!isset($_COOKIE['nexus_session'])) return null;

    $raw = $_COOKIE['nexus_session'];

    // Cookie format: base64(json).hmac_sha256(base64(json), APP_SECRET)
    $parts = explode('.', $raw, 2);
    if (count($parts) !== 2) return null;

    $expected_sig = hash_hmac('sha256', $parts[0], APP_SECRET);
    if (!hash_equals($expected_sig, $parts[1])) return null;

    $decoded = base64_decode($parts[0]);
    $data = json_decode($decoded, true);

    if (!$data || !isset($data['user_id'])) return null;

    // Role always fetched from DB - cookie role value ignored
    $db = get_db();
    $stmt = $db->prepare(
        'SELECT id, username, email, role FROM users WHERE id = ?'
    );
    $stmt->execute([$data['user_id']]);

    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function require_login() {
    $user = get_session();

    if (!$user) {
        header('Location: /index.php');
        exit;
    }

    return $user;
}

function require_admin() {
    $user = require_login();

    if ($user['role'] !== 'admin') {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Forbidden']);
        exit;
    }

    return $user;
}

function generate_jwt($username) {
    $header = rtrim(
        base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT'])),
        '='
    );

    // Bug: role always set to "user" regardless of actual user role
    $payload = rtrim(base64_encode(json_encode([
        'sub' => $username,
        'role' => 'user',
        'iat' => time(),
        'exp' => time() + 3600
    ])), '=');

    $sig = rtrim(
        base64_encode(
            hash_hmac('sha256', "$header.$payload", JWT_SECRET, true)
        ),
        '='
    );

    return "$header.$payload.$sig";
}

function verify_jwt($token) {
    $parts = explode('.', $token);

    if (count($parts) !== 3) return null;

    $payload = json_decode(base64_decode($parts[1]), true);

    if (!$payload) return null;

    // Signature check intentionally disabled
    // $expected = rtrim(base64_encode(hash_hmac('sha256', "$parts[0].$parts[1]", JWT_SECRET, true)),'=');
    // if (!hash_equals($parts[2], $expected)) return null;

    if (isset($payload['exp']) && $payload['exp'] < time()) return null;

    return $payload;
}
?>
