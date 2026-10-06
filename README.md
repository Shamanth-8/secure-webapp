# 🔐 Secure Web App + SAST Pipeline

> **Description: ** Built intentionally vulnerable Flask app, identified 12 OWASP flaws, applied fixes, deployed secure version in Docker with hardened CI/CD pipeline.

---

## What This Project Is

Two versions of the same Flask web application:
1. `vulnerable_app/app.py` — intentionally broken with OWASP Top 10 flaws
2. `secure_app/app.py` — fixed with detailed annotations explaining every change

Side-by-side comparison teaches you to **recognise insecure patterns** AND **know exactly how to fix them** — the core skill of an AppSec engineer.

---

## OWASP Top 10 (2021) Covered

| # | Category | Flaw in vulnerable_app | Fix in secure_app |
|---|----------|------------------------|-------------------|
| A01 | Broken Access Control | Admin panel readable if cookie forged; IDOR lets any user read any note | Server-side role check reads from DB; notes query always filters by session user_id |
| A02 | Cryptographic Failures | MD5 password hashing; secrets on HTTP | bcrypt (cost=12) with random salt; HTTPS enforced |
| A03 | Injection | SQL injection in login + search; command injection in ping; XSS in comments | Parameterised queries; subprocess list (no shell=True); bleach sanitisation |
| A04 | Insecure Design | No rate limiting; no password complexity | Flask-Limiter; WTForms validators; minimum 12-char passwords |
| A05 | Security Misconfiguration | `debug=True`; hardcoded `SECRET_KEY`; verbose error pages | debug off; secret from env var; generic error pages; security headers |
| A07 | Auth Failures | No session regeneration; session fixation possible | `session.clear()` + session.clear() on login regenerates session ID |
| A08 | Software Integrity | Unpinned dependencies | Exact versions in requirements.txt; pip-audit in CI |
| A09 | Logging Failures | No auth event logging | `security_logger` logs all login events, failures, anomalies |
| A10 | SSRF | User-supplied URLs fetched server-side (metadata endpoint accessible) | URL allowlist; private IP range block; scheme validation |

---

## Why Each Security Control Works

### Parameterised Queries (SQL Injection Fix)
**Vulnerable:**
```python
query = f"SELECT * FROM users WHERE username='{username}'"
conn.execute(query)  # username = "admin' --" bypasses password check
```

**Secure:**
```python
conn.execute("SELECT * FROM users WHERE username = ?", (username,))
```
The `?` placeholder is handled by the database driver, not string substitution. The database treats the entire value as data, never as SQL code. A single quote in the input is just a character, not a SQL delimiter.

### bcrypt Password Hashing
MD5 is a cryptographic hash, not a password hash. It's:
- Extremely fast (designed for file integrity, not authentication)
- GPU-crackable: ~10 billion MD5 hashes/second on consumer hardware
- Has no salt by default (rainbow tables work)

bcrypt is purpose-built for passwords:
- Computationally slow by design (adjustable work factor)
- Includes a random salt automatically
- Taking 100ms per check makes brute force 10 billion times harder

```python
# Insecure: MD5, no salt, trivially reversed
hashlib.md5(password.encode()).hexdigest()

# Secure: bcrypt, random salt embedded, work factor = 12
bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

### CSRF Tokens
Cross-Site Request Forgery tricks a logged-in user's browser into making requests they didn't intend. A bank transfer form with no CSRF protection can be triggered by visiting `evil.com`.

Flask-WTF generates a hidden token in every form. The token is validated server-side on POST. An attacker on a different domain cannot read the token (same-origin policy), so the forged request fails.

### bleach HTML Sanitisation (XSS Fix)
```python
# Insecure: raw user input stored and rendered
content = request.form["comment"]

# Secure: strip all HTML before storage
sanitised = bleach.clean(content, tags=[], strip=True)
# "<script>alert(1)</script>Hello" → "Hello"
```

### Command Injection Prevention
```python
# Insecure: shell=True + string interpolation
subprocess.run(f"ping -c 1 {host}", shell=True)
# host = "localhost; cat /etc/passwd" → runs both commands

# Secure: list arguments + no shell
subprocess.run(["/bin/ping", "-c", "1", host])
# With a list, each element is a separate argument
# Shell metacharacters (;, |, &&) are never interpreted
```

### SSRF Prevention
Server-Side Request Forgery: the server fetches a URL the attacker supplies. The server's network position means it can reach:
- Cloud metadata API (`169.254.169.254`) → AWS/GCP/Azure instance metadata, including IAM credentials
- Internal services not exposed to the internet

Fix: parse the URL, resolve the IP, and reject private/loopback ranges.

---

## SAST Pipeline

Static Application Security Testing runs at every commit — no running code required.

### Bandit
Python-specific SAST. Bandit detects:
- `B608` — SQL injection (string formatting in queries)
- `B602` — `subprocess` with `shell=True`
- `B324` — weak hash function (MD5, SHA1)
- `B105` — hardcoded password
- `B201` — Flask debug mode enabled
- `B310` — URL open without validation (SSRF risk)

Run locally:
```bash
# Scan with all severities
bandit -r secure_app/ -ll

# See what Bandit catches in the vulnerable app
bandit -r vulnerable_app/ -l
```

### GitHub Actions SAST Workflow
```
Push to main
    → bandit scans vulnerable_app (informational)
    → bandit scans secure_app (fails on HIGH severity)
    → pip-audit checks for CVEs in dependencies
    → gitleaks scans git history for secrets
    → SARIF results uploaded to GitHub Security tab
```

---

## Docker Hardening

### Non-Root User
```dockerfile
RUN useradd --uid 1001 appuser
USER appuser
```
If an attacker achieves RCE inside the container, they run as `appuser` — no write access to the filesystem, no ability to install tools or escalate.

### Read-Only Filesystem
```yaml
read_only: true
tmpfs:
  - /tmp:size=64m,noexec,nosuid
```
Malware cannot write itself to disk. Tools cannot be installed. Even if code executes, the filesystem is immutable.

### No New Privileges
```yaml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
```
Prevents privilege escalation via `setuid` binaries. The container process cannot gain capabilities it wasn't started with.

### Internal Network Isolation
```yaml
networks:
  internal:
    internal: true
```
The app container cannot make outbound internet connections. SSRF payloads that try to reach external services are blocked at the network layer.

---

## Running the Project

### Vulnerable app (for learning/testing)
```bash
cd secure-webapp
pip install flask
python vulnerable_app/app.py
# Visit http://localhost:5000
# Try: username = admin' --   password = anything  (SQL injection)
```

### Secure app
```bash
pip install -r requirements.txt
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python secure_app/app.py
```

### Docker
```bash
# Generate a strong secret
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Build and run
docker-compose up --build

# Scan the container image for vulnerabilities
docker scout cves secure-flask-app:latest
```

### Tests
```bash
pytest tests/ -v --cov=secure_app --cov-report=html
```

---

## Key Design Decisions

**Why Flask over Django?**
Flask is minimal — every security control must be added deliberately. This makes the "before/after" comparison clear. Django includes many controls by default (CSRF middleware, ORM parameterisation), which would make the vulnerable version harder to construct educationally.

**Why SQLite over PostgreSQL?**
Zero setup friction. The security concepts (parameterised queries, password hashing) are identical regardless of database. A real deployment would use PostgreSQL with connection pooling.

**Why bleach over a CSP policy alone?**
CSP is a defence-in-depth measure that the browser enforces. bleach is server-side sanitisation that removes the payload before it ever reaches storage. You want both: sanitise on input, enforce CSP on output.

**Why bcrypt at cost 12?**
Cost 12 takes ~250ms on modern hardware. That's imperceptible to a user logging in once but means an attacker trying 1 billion passwords takes ~8 years per hash. Cost 10 is a common default; 12 is slightly more future-proof.

**Why gunicorn over Flask dev server?**
Flask's dev server is single-threaded, unoptimised, and exposes an interactive debugger. Gunicorn is a production WSGI server with worker process management, graceful restarts, and no debug backdoors.
