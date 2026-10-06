"""
secure_app/app.py — Hardened Flask application.

This is the fixed version of vulnerable_app/app.py.
Every fix is annotated with:
    # FIX: <OWASP category> — <what was wrong> → <what we did>

Reading this file alongside vulnerable_app/app.py teaches you exactly
how to remediate each OWASP Top 10 category in a Python/Flask stack.

SECURITY CONTROLS APPLIED:
    ✅ Parameterised queries (SQLi prevention)
    ✅ bcrypt password hashing
    ✅ CSRF protection (Flask-WTF)
    ✅ Rate limiting (Flask-Limiter)
    ✅ Input validation & sanitisation (bleach, wtforms)
    ✅ Secure session configuration
    ✅ Principle of least privilege (role checks server-side)
    ✅ No sensitive data in API responses
    ✅ Command injection prevention (no shell=True)
    ✅ SSRF prevention (URL allowlist)
    ✅ Security headers (Flask-Talisman / manual)
    ✅ Structured security logging
"""

import os
import re
import logging
import sqlite3
import subprocess
import ipaddress
from datetime import timedelta
from functools import wraps

import bleach                          # HTML sanitisation
import bcrypt                          # password hashing
from flask import (
    Flask, request, render_template,
    session, redirect, url_for, jsonify, abort, g
)
from flask_wtf import FlaskForm        # CSRF protection
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter      # rate limiting
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length, Regexp

# ---------------------------------------------------------------------------
# Structured security logging
# FIX: A09 — Log all auth events (success, failure, suspicious activity)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
security_logger = logging.getLogger("security")


# ---------------------------------------------------------------------------
# App initialisation
# ---------------------------------------------------------------------------

app = Flask(__name__)

# FIX: A05 — Secret key from environment variable, never hardcoded.
#      Generate with: python -c "import secrets; print(secrets.token_hex(32))"
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)

# FIX: A05 — Debug mode off in production. Read from env var.
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

# FIX: A07 — Secure session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,        # Only send cookie over HTTPS
    SESSION_COOKIE_HTTPONLY=True,      # JS cannot read session cookie → XSS mitigation
    SESSION_COOKIE_SAMESITE="Lax",     # CSRF mitigation
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    WTF_CSRF_TIME_LIMIT=3600,
)

DATABASE = os.environ.get("DATABASE_PATH", "secure.db")

# FIX: A03 — CSRF protection on all POST forms
csrf = CSRFProtect(app)

# FIX: A04 — Rate limiting to prevent brute force and enumeration
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


# ---------------------------------------------------------------------------
# Security headers middleware
# FIX: A05 — Add security headers to every response
# ---------------------------------------------------------------------------

@app.after_request
def add_security_headers(response):
    """
    These headers tell the browser to enforce security policies:
    - CSP: blocks XSS by specifying where scripts can load from
    - HSTS: forces HTTPS for 1 year
    - X-Frame-Options: prevents clickjacking
    - X-Content-Type: prevents MIME-sniffing attacks
    """
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"]           = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=()"
    return response


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row   # row["column"] access
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,  -- FIX: bcrypt hash, not MD5
            role TEXT DEFAULT 'user' NOT NULL,
            email TEXT,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,     -- FIX: always owned by a user
            content TEXT NOT NULL,
            is_private INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    # FIX: A02 — bcrypt hash, not MD5
    admin_hash = bcrypt.hashpw(b"ChangeMe!SecureP@ss1", bcrypt.gensalt()).decode()
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("admin", admin_hash, "admin"),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------

def login_required(f):
    """Redirect unauthenticated users to login."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """
    FIX: A01 — Server-side role enforcement.
    Role is re-read from the database, not trusted from the session cookie.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            abort(401)
        db   = get_db()
        user = db.execute(
            "SELECT role FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if not user or user["role"] != "admin":
            security_logger.warning(
                "Privilege escalation attempt by user_id=%s", session.get("user_id")
            )
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Forms (WTForms + CSRF)
# FIX: A03/A07 — Input validation at the form layer, CSRF token on every form
# ---------------------------------------------------------------------------

class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=64),
            Regexp(r"^[a-zA-Z0-9_]+$", message="Alphanumeric and underscore only"),
        ],
    )
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])


class RegisterForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=64),
            Regexp(r"^[a-zA-Z0-9_]+$", message="Alphanumeric and underscore only"),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=12, max=128, message="Password must be at least 12 characters"),
        ],
    )


class CommentForm(FlaskForm):
    comment = StringField("Comment", validators=[DataRequired(), Length(max=500)])


# ---------------------------------------------------------------------------
# A03 FIX: Authentication with parameterized query + bcrypt
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")   # FIX: A04 — brute force protection
def login():
    """
    FIX: A03 — Parameterised query prevents SQL injection.
    FIX: A02 — bcrypt comparison (timing-safe, salted).
    FIX: A04 — Rate limited to 10 attempts/minute per IP.
    FIX: A07 — Session regeneration on login (session fixation prevention).
    """
    form  = LoginForm()
    error = None

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data.encode()

        db   = get_db()
        # FIX: Parameterised query — ? placeholder, never string interpolation
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and bcrypt.checkpw(password, user["password_hash"].encode()):
            # FIX: A07 — Regenerate session ID on login (prevents session fixation)
            session.clear()
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            session.permanent   = True

            security_logger.info("Successful login: username=%s ip=%s", username, request.remote_addr)
            return redirect(url_for("dashboard"))
        else:
            # FIX: A09 — Log failed attempts
            security_logger.warning(
                "Failed login attempt: username=%s ip=%s", username, request.remote_addr
            )
            error = "Invalid credentials"   # Generic message (no username enumeration)

    if request.method == "POST" and form.errors:
        security_logger.warning("Login form rejected: errors=%s ip=%s", form.errors, request.remote_addr)
    return render_template("login.html", form=form, error=error)


# ---------------------------------------------------------------------------
# A03 FIX: Search with parameterised query + output escaping
# ---------------------------------------------------------------------------

@app.route("/search")
@login_required
def search():
    """
    FIX: A03 — Parameterised LIKE query prevents SQL injection.
    FIX: A03 — Results rendered in Jinja2 template with auto-escaping.
    FIX: A01 — Users only see their own notes.
    """
    q    = request.args.get("q", "")[:100]  # length cap
    db   = get_db()
    # FIX: parameterised query — % wildcards in the VALUE, not in the SQL
    rows = db.execute(
        "SELECT * FROM notes WHERE content LIKE ? AND user_id = ?",
        (f"%{q}%", session["user_id"]),
    ).fetchall()
    return render_template("search.html", results=rows, query=q)


# ---------------------------------------------------------------------------
# A01 FIX: IDOR prevention — always filter by session user_id
# ---------------------------------------------------------------------------

@app.route("/notes/<int:note_id>")
@login_required
def get_note(note_id: int):
    """
    FIX: A01 — Query includes user_id from session, not from user input.
    A user cannot access another user's notes by changing the URL.
    """
    db   = get_db()
    note = db.execute(
        # FIX: WHERE user_id = session["user_id"] — ownership enforced
        "SELECT * FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session["user_id"]),
    ).fetchone()

    if not note:
        abort(404)   # Same response for "not found" and "not yours" → no enumeration

    return render_template("note.html", note=note)


# ---------------------------------------------------------------------------
# A03 FIX: XSS prevention — bleach sanitisation + Jinja2 auto-escaping
# ---------------------------------------------------------------------------

ALLOWED_TAGS: list[str] = []  # No HTML allowed in comments

@app.route("/comment", methods=["GET", "POST"])
@login_required
def comment():
    """
    FIX: A03 — Stored XSS prevention:
    1. bleach.clean() strips ALL HTML tags before storage
    2. Jinja2 templates auto-escape output ({{ var }} vs {{ var|safe }})
    3. FlaskForm CSRF token prevents cross-site form submission
    """
    form = CommentForm()
    db   = get_db()

    if form.validate_on_submit():
        # FIX: Strip all HTML — bleach.clean with no allowed tags
        sanitised = bleach.clean(form.comment.data, tags=ALLOWED_TAGS, strip=True)
        db.execute(
            "INSERT INTO notes (user_id, content) VALUES (?, ?)",
            (session["user_id"], sanitised),
        )
        db.commit()

    rows = db.execute(
        "SELECT content FROM notes WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    # FIX: Rendered in template — Jinja2 auto-escaping is ON by default
    return render_template("comments.html", form=form, comments=rows)


# ---------------------------------------------------------------------------
# A03 FIX: Command injection prevention
# ---------------------------------------------------------------------------

# Allowlist of valid IPv4/IPv6 addresses and hostnames
HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.\-]{1,253}$")

@app.route("/ping")
@login_required
def ping():
    """
    FIX: A03 — Command injection prevention:
    1. Validate input against a strict allowlist regex
    2. Use subprocess with a list argument (NO shell=True)
    3. Absolute path to ping binary

    With shell=False and a list, user input cannot inject shell metacharacters.
    """
    host = request.args.get("host", "")

    # FIX: Validate input — only hostnames/IPs allowed
    if not HOSTNAME_RE.match(host):
        abort(400, "Invalid hostname")

    # FIX: subprocess with list (shell=False by default) — no injection possible
    result = subprocess.run(
        ["/bin/ping", "-c", "1", "-W", "2", host],  # FIX: list, not shell string
        capture_output=True,
        text=True,
        timeout=5,   # prevent resource exhaustion
    )
    # FIX: Output rendered in template with auto-escaping
    return render_template("ping.html", host=host, output=result.stdout)


# ---------------------------------------------------------------------------
# A10 FIX: SSRF prevention via URL allowlist
# ---------------------------------------------------------------------------

ALLOWED_DOMAINS = {"example.com", "api.example.com"}

def is_safe_url(url: str) -> bool:
    """
    FIX: A10 — SSRF prevention:
    1. Parse the URL and extract the hostname
    2. Reject private/loopback IPs (cloud metadata, internal services)
    3. Only allow URLs from an explicit allowlist of trusted domains
    """
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname or ""
        # Block private/loopback IP ranges
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return False
        except ValueError:
            pass   # hostname is a domain, not an IP — check allowlist
        return hostname in ALLOWED_DOMAINS
    except Exception:
        return False


@app.route("/fetch")
@login_required
def fetch_url():
    """FIX: A10 — SSRF prevented by is_safe_url() allowlist check."""
    import urllib.request
    url = request.args.get("url", "")
    if not is_safe_url(url):
        security_logger.warning("SSRF attempt blocked: url=%s ip=%s", url, request.remote_addr)
        abort(400, "URL not allowed")
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310
        return resp.read().decode()[:10000]


# ---------------------------------------------------------------------------
# A07 FIX: Registration with bcrypt + complexity requirements
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour")   # FIX: A04 — prevent mass account creation
def register():
    """
    FIX: A02 — bcrypt hashing (work factor 12 — adjustable as hardware improves)
    FIX: A04 — rate limited, minimum password length enforced
    FIX: A07 — email verification would go here in production
    """
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        # FIX: bcrypt with random salt, work factor 12
        hashed   = bcrypt.hashpw(form.password.data.encode(), bcrypt.gensalt(rounds=12)).decode()
        db       = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hashed),
            )
            db.commit()
            security_logger.info("New user registered: username=%s ip=%s", username, request.remote_addr)
        except sqlite3.IntegrityError:
            return render_template("register.html", form=form, error="Username taken")
        return redirect(url_for("login"))
    if request.method == "POST" and form.errors:
        security_logger.warning("Register form rejected: errors=%s ip=%s", form.errors, request.remote_addr)
    return render_template("register.html", form=form)


# ---------------------------------------------------------------------------
# A01 FIX: Admin panel with server-side role check
# ---------------------------------------------------------------------------

@app.route("/admin")
@login_required
@admin_required   # FIX: role read from DB, not session cookie
def admin():
    db    = get_db()
    # FIX: Only return id, username, role — no password hashes
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    return render_template("admin.html", users=users)


# ---------------------------------------------------------------------------
# A02 FIX: Export without sensitive data
# ---------------------------------------------------------------------------

@app.route("/export")
@login_required
@admin_required
def export():
    """
    FIX: A02 — Password hashes NEVER returned in API responses.
    FIX: A01 — Admin-only endpoint.
    """
    db    = get_db()
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    # FIX: No password_hash in the response
    return jsonify([{"id": u["id"], "username": u["username"], "role": u["role"]} for u in users])


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session["username"])


@app.route("/logout")
def logout():
    # FIX: A07 — Clear ALL session data on logout
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# FIX: A05 — Generic error handler (no stack traces to users)
# ---------------------------------------------------------------------------

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(500)
def handle_error(e):
    """
    FIX: A05 — Return a generic error page.
    Stack traces and internal paths are logged server-side, never shown to users.
    """
    security_logger.error("HTTP %s: %s | path=%s ip=%s", e.code, e.description, request.path, request.remote_addr)
    return render_template("error.html", error_code=e.code), e.code


if __name__ == "__main__":
    init_db()
    # FIX: host="127.0.0.1" — only listen locally. Let nginx/gunicorn handle external traffic.
    app.run(debug=False, host="127.0.0.1", port=5001)
