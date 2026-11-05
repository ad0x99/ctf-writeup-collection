#!/usr/bin/env python3
import os
import re
import sqlite3
import subprocess
import hashlib
from functools import wraps
from flask import (
    Flask, request, render_template, redirect,
    url_for, session, g
)

app = Flask(__name__)
app.secret_key = os.environ.get(&#34;FLASK_SECRET&#34;)
if not app.secret_key:
    raise RuntimeError(&#34;FLASK_SECRET environment variable not set&#34;)

DATABASE = &#34;/opt/netops/netops.db&#34;


def get_db():
    db = getattr(g, &#34;_database&#34;, None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, &#34;_database&#34;, None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute(&#34;&#34;&#34;
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT &#39;viewer&#39;
        )
    &#34;&#34;&#34;)
    db.execute(&#34;&#34;&#34;
        CREATE TABLE IF NOT EXISTS audit_log (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action   TEXT,
            detail   TEXT,
            ts       TEXT
        )
    &#34;&#34;&#34;)
    pw = hashlib.md5(b&#34;C0rp$N3tS3cur3!&#34;).hexdigest()
    db.execute(
        &#34;INSERT OR IGNORE INTO users (username, password, role) VALUES (?,?,?)&#34;,
        (&#34;netops&#34;, pw, &#34;operator&#34;)
    )
    db.commit()
    db.close()


def log_action(username, action, detail=&#34;&#34;):
        pass


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get(&#34;user&#34;):
            return redirect(url_for(&#34;login&#34;))
        return f(*args, **kwargs)
    return decorated


# need to modify this filter.
BLOCK_RE = re.compile(
    r&#34;(union\s+select|drop\s+table|insert\s+into|xp_cmdshell)&#34;,
    re.IGNORECASE
)

FAKE_AUDIT = [
    (&#34;jmartin&#34;,  &#34;LOGIN_OK&#34;,     &#34;&#34;,           &#34;2026-01-14 08:03:11&#34;),
    (&#34;jmartin&#34;,  &#34;HEALTH_CHECK&#34;, &#34;10.0.1.4&#34;,   &#34;2026-01-14 08:04:02&#34;),
    (&#34;jmartin&#34;,  &#34;HEALTH_CHECK&#34;, &#34;10.0.1.7&#34;,   &#34;2026-01-14 08:04:28&#34;),
    (&#34;jmartin&#34;,  &#34;LOGOUT&#34;,       &#34;&#34;,           &#34;2026-01-14 08:31:55&#34;),
    (&#34;netops&#34;,   &#34;LOGIN_OK&#34;,     &#34;&#34;,           &#34;2026-01-14 09:17:40&#34;),
    (&#34;netops&#34;,   &#34;HEALTH_CHECK&#34;, &#34;10.0.0.1&#34;,   &#34;2026-01-14 09:18:03&#34;),
    (&#34;netops&#34;,   &#34;HEALTH_CHECK&#34;, &#34;10.0.2.12&#34;,  &#34;2026-01-14 09:19:47&#34;),
    (&#34;netops&#34;,   &#34;LOGOUT&#34;,       &#34;&#34;,           &#34;2026-01-14 09:44:22&#34;),
    (&#34;svc-mon&#34;,  &#34;LOGIN_OK&#34;,     &#34;&#34;,           &#34;2026-01-14 10:00:01&#34;),
    (&#34;svc-mon&#34;,  &#34;HEALTH_CHECK&#34;, &#34;10.0.1.1&#34;,   &#34;2026-01-14 10:00:04&#34;),
    (&#34;svc-mon&#34;,  &#34;HEALTH_CHECK&#34;, &#34;10.0.1.2&#34;,   &#34;2026-01-14 10:00:07&#34;),
    (&#34;svc-mon&#34;,  &#34;HEALTH_CHECK&#34;, &#34;10.0.1.3&#34;,   &#34;2026-01-14 10:00:10&#34;),
    (&#34;svc-mon&#34;,  &#34;HEALTH_CHECK&#34;, &#34;10.0.1.4&#34;,   &#34;2026-01-14 10:00:13&#34;),
    (&#34;svc-mon&#34;,  &#34;LOGOUT&#34;,       &#34;&#34;,           &#34;2026-01-14 10:00:16&#34;),
    (&#34;jmartin&#34;,  &#34;LOGIN_FAIL&#34;,   &#34;&#34;,           &#34;2026-01-14 11:02:38&#34;),
    (&#34;jmartin&#34;,  &#34;LOGIN_OK&#34;,     &#34;&#34;,           &#34;2026-01-14 11:02:51&#34;),
    (&#34;jmartin&#34;,  &#34;HEALTH_CHECK&#34;, &#34;10.0.2.5&#34;,   &#34;2026-01-14 11:03:14&#34;),
    (&#34;jmartin&#34;,  &#34;LOGOUT&#34;,       &#34;&#34;,           &#34;2026-01-14 11:28:07&#34;),
    (&#34;netops&#34;,   &#34;LOGIN_OK&#34;,     &#34;&#34;,           &#34;2026-01-15 07:55:30&#34;),
    (&#34;netops&#34;,   &#34;HEALTH_CHECK&#34;, &#34;10.0.0.254&#34;, &#34;2026-01-15 07:56:01&#34;),
]


@app.route(&#34;/&#34;)
def index():
    return render_template(&#34;index.html&#34;)


@app.route(&#34;/internal&#34;, methods=[&#34;GET&#34;, &#34;POST&#34;])
def login():
    error = None

    if request.method == &#34;POST&#34;:
        username = request.form.get(&#34;username&#34;, &#34;&#34;)
        password = request.form.get(&#34;password&#34;, &#34;&#34;)

        if BLOCK_RE.search(username) or BLOCK_RE.search(password):
            log_action(username, &#34;LOGIN_BLOCKED&#34;)
            error = &#34;Invalid username or password.&#34;
        else:
            pw_hash = hashlib.md5(password.encode()).hexdigest()
            # Vulnerable: direct string interpolation — no parameterisation
            query = (
                &#34;SELECT id, username, role FROM users &#34;
                &#34;WHERE username = &#39;%s&#39; AND password = &#39;%s&#39;&#34;
            ) % (username, pw_hash)

            try:
                db = get_db()
                row = db.execute(query).fetchone()
                if row:
                    session[&#34;user&#34;] = row[&#34;username&#34;]
                    session[&#34;role&#34;] = row[&#34;role&#34;]
                    log_action(row[&#34;username&#34;], &#34;LOGIN_OK&#34;)
                    return redirect(url_for(&#34;dashboard&#34;))
                else:
                    error = &#34;Invalid username or password.&#34;
                    log_action(username, &#34;LOGIN_FAIL&#34;)
            except Exception:
                error = &#34;Invalid username or password.&#34;
                log_action(username, &#34;LOGIN_ERROR&#34;)

    return render_template(&#34;login.html&#34;, error=error)


@app.route(&#34;/internal/dashboard&#34;)
@login_required
def dashboard():
    db = get_db()
    real_logs = db.execute(
        &#34;SELECT username, action, detail, ts FROM audit_log &#34;
        &#34;ORDER BY ts DESC LIMIT 8&#34;
    ).fetchall()

    combined = [(r[&#34;username&#34;], r[&#34;action&#34;], r[&#34;detail&#34;], r[&#34;ts&#34;])
                for r in real_logs]
    combined += list(FAKE_AUDIT)

    return render_template(
        &#34;dashboard.html&#34;,
        current_user=session[&#34;user&#34;],
        role=session[&#34;role&#34;],
        logs=combined
    )


# vulnerable to newline injection (\n / %0a), fix soon.
PING_BLOCK_RE = re.compile(r&#34;[;|`$&amp;]&#34;)


@app.route(&#34;/internal/health&#34;, methods=[&#34;GET&#34;, &#34;POST&#34;])
@login_required
def health_check():
    output  = None
    cmd_err = None
    target  = &#34;&#34;

    if request.method == &#34;POST&#34;:
        target = request.form.get(&#34;target&#34;, &#34;&#34;).strip()

        if not target:
            cmd_err = &#34;No target specified.&#34;
        elif len(target) &gt; 100:
            cmd_err = &#34;Invalid hostname or IP address.&#34;
        elif PING_BLOCK_RE.search(target):
            cmd_err = &#34;Invalid hostname or IP address.&#34;
        else:
            try:
                proc = subprocess.Popen(
                    &#34;ping -c 2 -W 1 &#34; + target,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                try:
                    output, _ = proc.communicate(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.stdout.close()
                    output = &#34;[process running in background]&#34;

                log_action(session[&#34;user&#34;], &#34;HEALTH_CHECK&#34;,
                           target.split(&#34;\n&#34;)[0])
            except Exception:
                cmd_err = &#34;An error occurred.&#34;

    return render_template(
        &#34;health.html&#34;,
        current_user=session[&#34;user&#34;],
        role=session[&#34;role&#34;],
        output=output,
        error=cmd_err,
        target=target
    )


@app.route(&#34;/internal/logout&#34;)
def logout():
    user = session.get(&#34;user&#34;, &#34;unknown&#34;)
    session.clear()
    log_action(user, &#34;LOGOUT&#34;)
    return redirect(url_for(&#34;login&#34;))


@app.errorhandler(404)
def not_found(e):
    return render_template(&#34;404.html&#34;), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template(&#34;404.html&#34;), 403


if __name__ == &#34;__main__&#34;:
    init_db()
    app.run(host=&#34;0.0.0.0&#34;, port=5050, debug=False)
