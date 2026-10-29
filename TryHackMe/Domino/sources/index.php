<?php
require_once __DIR__ . '/auth.php';

$user = get_session();

if ($user) {
    header('Location: /dashboard.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username && $password) {
        $db = get_db();

        $stmt = $db->prepare(
            'SELECT id, username, email, role, password_hash
             FROM users WHERE username = ?'
        );
        $stmt->execute([$username]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row && password_verify($password, $row['password_hash'])) {
            $cookie_data = base64_encode(json_encode([
                'user_id' => $row['id'],
                'username' => $row['username'],
                'role' => $row['role']
            ]));

            $sig = hash_hmac('sha256', $cookie_data, APP_SECRET);

            setcookie(
                'nexus_session',
                $cookie_data . '.' . $sig,
                0,
                '/',
                '',
                false,
                false
            );

            header('Location: /dashboard.php');
            exit;
        } else {
            $error = 'Invalid credentials';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NexusCorp Portal</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body class="login-page">
<div class="login-box">
    <div class="logo">
        <span class="logo-icon">&#9650;</span> NexusCorp
    </div>

    <h2>Employee Portal</h2>

    <?php if ($error): ?>
        <div class="alert alert-danger">
            <?= htmlspecialchars($error) ?>
        </div>
    <?php endif; ?>

    <form method="POST" action="/index.php">
        <div class="form-group">
            <label>Username</label>
            <input
                type="text"
                name="username"
                placeholder="firstname.lastname"
                required
            >
        </div>

        <div class="form-group">
            <label>Password</label>
            <input
                type="password"
                name="password"
                placeholder="Password"
                required
            >
        </div>

        <button type="submit" class="btn-primary">Sign In</button>
    </form>

    <div class="links">
        <a href="/forgot.php">Forgot password?</a> -
        <a href="/team.php">Our Team</a>
    </div>
</div>
</body>
</html>