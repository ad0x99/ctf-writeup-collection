<?php
require_once __DIR__ . '/../auth.php';

$user = require_login();
$db = get_db();

$stmt = $db->prepare(
    'SELECT t.id, t.subject, t.created_at, t.viewed
     FROM tickets t
     WHERE t.user_id = ?
     ORDER BY t.created_at DESC'
);

$stmt->execute([$user['id']]);
$tickets = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Support - NexusCorp</title>
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
        <a href="/logout.php">Logout</a>
    </div>
</nav>

<div class="container">
    <div style="display:flex;justify-content:space-between;align-items:center">
        <h1>Support Tickets</h1>
        <a href="/support/create.php" class="btn-primary">New Ticket</a>
    </div>

    <?php if (empty($tickets)): ?>
        <div class="card">
            <p>
                No tickets yet.
                <a href="/support/create.php">Open your first ticket</a>.
            </p>
        </div>
    <?php else: ?>
        <table class="data-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Subject</th>
                    <th>Status</th>
                    <th>Created</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($tickets as $t): ?>
                    <tr>
                        <td><?= $t['id'] ?></td>
                        <td><?= htmlspecialchars($t['subject']) ?></td>
                        <td>
                            <?= $t['viewed']
                                ? '<span class="badge badge-green">Reviewed</span>'
                                : '<span class="badge badge-yellow">Pending</span>' ?>
                        </td>
                        <td><?= $t['created_at'] ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>
</body>
</html>