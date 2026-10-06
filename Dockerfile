# Dockerfile — Hardened container for the secure Flask app
#
# WHY DOCKER HARDENING MATTERS:
#   A vulnerable container can give an attacker a pivot point into your
#   infrastructure even if the app code is secure. This Dockerfile implements
#   CIS Docker Benchmark recommendations.
#
# HARDENING TECHNIQUES APPLIED:
#   1. Minimal base image (python:3.11-slim) — fewer packages = fewer CVEs
#   2. Non-root user — if container is compromised, attacker has minimal privileges
#   3. Read-only filesystem where possible
#   4. No new privileges flag (set in docker-compose)
#   5. Multi-stage build — dev deps not in final image
#   6. Pinned base image digest (production: use --platform linux/amd64 with digest)
#   7. Healthcheck — container reports unhealthy if app crashes

# ============================================================
# Stage 1: Builder — install dependencies
# ============================================================
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies (needed for bcrypt compilation)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ============================================================
# Stage 2: Runtime — minimal image
# ============================================================
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="Secure Flask App"
LABEL org.opencontainers.image.description="OWASP-hardened Flask application"

# Security: create a non-root user
# WHY: if an attacker achieves RCE, they run as 'appuser' (no root, no sudo)
RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application code (templates live in secure_app/templates)
COPY secure_app/ ./secure_app/
COPY gunicorn.conf.py ./

# Security: change ownership to non-root user
RUN chown -R appuser:appgroup /app

# Create writable directory for SQLite (only place writes are allowed)
RUN mkdir -p /data && chown appuser:appgroup /data

# Switch to non-root user
USER appuser

# Run with gunicorn (production WSGI server, not Flask dev server)
# WHY gunicorn over flask run:
#   - Flask dev server is single-threaded, not safe for production
#   - Gunicorn handles concurrent requests, has worker management
#   - Gunicorn does NOT expose an interactive debugger
EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/login')" || exit 1

ENV DATABASE_PATH=/data/secure.db \
    FLASK_DEBUG=false \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# gunicorn.conf.py runs init_db() before workers start
CMD ["gunicorn", \
     "--config", "gunicorn.conf.py", \
     "--bind", "0.0.0.0:5001", \
     "--workers", "2", \
     "--worker-class", "sync", \
     "--timeout", "30", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "secure_app.app:app"]
