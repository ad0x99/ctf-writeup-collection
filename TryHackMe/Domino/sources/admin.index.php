<?php
require_once __DIR__ . '/../auth.php';

// Admin panel requires valid admin cookie OR valid admin JWT
$user = get_session();
$jwt_user = null;

if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
    $auth = $_SERVER['HTTP_AUTHORIZATION'];

    if (strpos($auth, 'Bearer ') === 0) {
        $token = substr($auth, 7);
        $jwt_user = verify_jwt($token);
    }
}

// Must have either admin cookie session or JWT with role=admin
if (!$user || $user['role'] !== 'admin') {
    if (!$jwt_user || ($jwt_user['role'] ?? '') !== 'admin') {
        http_response_code(403);
        include __DIR__ . '/../403.php';
        exit;
    }

    // JWT admin access - set display name
    $display = $jwt_user['sub'];
} else {
    $display = $user['username'];
}

// FLAG 2 is stored here
$flag2 = 'THM{bl1nd_x55_s3ss10n_h1j4ck_fl4g2}';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Panel - NexusCorp</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
<nav class="navbar">
    <div class="nav-brand">
        <span class="logo-icon">&#9650;</span> NexusCorp Admin
    </div>
    <div class="nav-links">
        <a href="/dashboard.php">Portal</a>
        <a href="/logout.php">Logout</a>
    </div>
</nav>

<div class="container">
    <div class="admin-header">
        <h1>Administration Console</h1>
        <p>
            Logged in as:
            <strong><?= htmlspecialchars($display) ?></strong>
        </p>
    </div>

    <div class="flag-box">
        <h3>System Status</h3>
        <p>Internal reference: <code><?= $flag2 ?></code></p>
    </div>

    <div class="card-grid">
        <div class="card">
            <h3>User Management</h3>
            <p>Manage employee accounts and permissions.</p>
            <a href="/api/users/profile.php?id=1" class="btn-secondary">
                View User API
            </a>
        </div>

        <div class="card">
            <h3>File System Access</h3>
            <p>Internal document viewer via authenticated API.</p>
            <p>
                <small>
                    GET /api/files.php?name=[path] with Bearer token
                </small>
            </p>
        </div>

        <div class="card">
            <h3>Support Queue</h3>
            <p>Pending tickets requiring admin review.</p>
            <?php
            $db = get_db();
            $count = $db->query(
                'SELECT COUNT(*) FROM tickets WHERE viewed = 0'
            )->fetchColumn();

            echo "<p><strong>$count</strong> unread tickets</p>";
            ?>
        </div>
    </div>
</div>
</body>
</html>