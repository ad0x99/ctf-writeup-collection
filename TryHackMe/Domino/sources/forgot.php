<?php
require_once __DIR__ . '/auth.php';

$msg = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');

    if ($username) {
        $db = get_db();

        $stmt = $db->prepare(
            'SELECT id, username, email, role FROM users WHERE username = ?'
        );
        $stmt->execute([$username]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            // Username enumeration: different message for unknown user
            $error = 'No account found with that username.';
        } elseif ($row['role'] === 'admin') {
            // Fix A: admin accounts never get a token, show email-sent message
            $masked = substr($row['email'], 0, 2)
                . str_repeat('*', 4)
                . substr($row['email'], strpos($row['email'], '@'));

            $msg = "Password reset instructions have been sent to $masked";
        } else {
            // Regular users: generate token and store
            // (token NOT bound to requesting user - logic flaw)
            $token = bin2hex(random_bytes(16));

            $db->prepare(
                'DELETE FROM reset_tokens WHERE user_id = ?'
            )->execute([$row['id']]);

            $db->prepare(
                'INSERT INTO reset_tokens (token, user_id) VALUES (?, ?)'
            )->execute([$token, $row['id']]);

            $msg = "Reset link sent. Check your email for instructions.";
        }
    }
}
?>
