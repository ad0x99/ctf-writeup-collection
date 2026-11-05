<?php
require_once __DIR__ . '/../auth.php';

$user = require_login();
$msg = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $subject = trim($_POST['subject'] ?? '');
    $message = trim($_POST['message'] ?? '');

    if ($subject && $message) {
        $db = get_db();

        // Message stored raw - no XSS filtering (intentional vulnerability)
        $stmt = $db->prepare(
            'INSERT INTO tickets (user_id, subject, message) VALUES (?, ?, ?)'
        );
        $stmt->execute([$user['id'], $subject, $message]);

        $msg = 'Ticket submitted successfully. An admin will review it shortly.';
    } else {
        $error = 'Subject and message are required.';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>New Ticket - NexusCorp</title>
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
    <h1>Open Support Ticket</h1>

    <?php if ($error): ?>
        <div class="alert alert-danger">
            <?= htmlspecialchars($error) ?>
        </div>
    <?php endif; ?>

    <?php if ($msg): ?>
        <div class="alert alert-success">
            <?= htmlspecialchars($msg) ?>
        </div>
    <?php endif; ?>

    <div class="card">
        <form method="POST" action="/support/create.php">
            <div class="form-group">
                <label>Subject</label>
                <input
                    type="text"
                    name="subject"
                    placeholder="Brief description of your issue"
                    required
                >
            </div>

            <div class="form-group">
                <label>Message</label>
                <textarea
                    name="message"
                    rows="8"
                    placeholder="Describe your issue in detail..."
                    required
                ></textarea>
            </div>

            <button type="submit" class="btn-primary">Submit Ticket</button>
            <a href="/support/index.php" class="btn-secondary">Cancel</a>
        </form>
    </div>
</div>
</body>
</html>