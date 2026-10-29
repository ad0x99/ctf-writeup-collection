<?php
require_once __DIR__ . '/auth.php';

$user = require_login();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - NexusCorp</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
<nav class="navbar">
    <div class="nav-brand">
        <span class="logo-icon">&#9650;</span> NexusCorp
    </div>

    <div class="nav-links">
        <a href="/dashboard.php">Dashboard</a>
        <a href="/support/index.php">Support</a>

        <?php if ($user['role'] === 'admin'): ?>
            <a href="/admin/index.php">Admin</a>
        <?php endif; ?>

        <a href="/logout.php">Logout</a>
    </div>
</nav>

<div class="container">
    <h1>Welcome, <?= htmlspecialchars($user['username']) ?></h1>

    <div class="card-grid">
        <div class="card">
            <h3>My Profile</h3>
            <p>
                <strong>Username:</strong>
                <?= htmlspecialchars($user['username']) ?>
            </p>
            <p>
                <strong>Email:</strong>
                <?= htmlspecialchars($user['email']) ?>
            </p>
            <p>
                <strong>Role:</strong>
                <?= htmlspecialchars($user['role']) ?>
            </p>
        </div>

        <div class="card">
            <h3>File Viewer</h3>
            <p>Access internal documents via the secure file API.</p>
            <p>
                <small>
                    Endpoint: <code>/api/files.php?name=</code>
                </small>
            </p>
            <p>
                <small>
                    Requires JWT authentication via
                    <code>/api/auth/token.php</code>
                </small>
            </p>
        </div>

        <div class="card">
            <h3>Quick Links</h3>
            <ul>
                <li>
                    <a href="/support/index.php">Support Tickets</a>
                </li>
                <li>
                    <a href="/support/create.php">Open Ticket</a>
                </li>
                <li>
                    <a href="/api/users/profile.php?id=<?= $user['id'] ?>">
                        My Profile API
                    </a>
                </li>
            </ul>
        </div>
    </div>
</div>
</body>
</html>