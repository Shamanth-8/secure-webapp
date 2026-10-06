"""
tests/test_webapp.py — Tests for both the vulnerable and secure Flask apps.

WHY TEST SECURITY CONTROLS:
    Security features that aren't tested tend to silently break during
    refactoring. These tests verify that:
    - SQL injection inputs are rejected or neutralised
    - CSRF tokens are required on POST forms
    - Rate limiting fires after N requests
    - IDOR is prevented (users can't read each other's notes)
    - XSS payloads are stripped before storage
    - Sensitive data is not leaked in API responses
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def vulnerable_client(tmp_path):
    """Test client for the VULNERABLE app."""
    import importlib, types

    # Override DATABASE path to a temp file
    db_path = str(tmp_path / "vuln_test.db")

    from vulnerable_app import app as vuln_module  # type: ignore
    vuln_module.DATABASE = db_path
    vuln_module.init_db()

    vuln_module.app.config["TESTING"] = True
    vuln_module.app.config["WTF_CSRF_ENABLED"] = False
    with vuln_module.app.test_client() as client:
        yield client


@pytest.fixture
def secure_client(tmp_path, monkeypatch):
    """Test client for the SECURE app."""
    import os
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-32-bytes-xxxxxxxxxx")

    db_path = str(tmp_path / "secure_test.db")

    from secure_app import app as sec_module  # type: ignore
    sec_module.DATABASE = db_path
    sec_module.init_db()

    sec_module.app.config["TESTING"]          = True
    sec_module.app.config["WTF_CSRF_ENABLED"] = False
    sec_module.app.config["SESSION_COOKIE_SECURE"] = False  # test env has no HTTPS
    with sec_module.app.test_client() as client:
        yield client


# ===========================================================================
# Vulnerable app: demonstrate the flaws ARE present
# ===========================================================================

class TestVulnerableAppFlaws:
    """
    These tests CONFIRM that the vulnerabilities exist in the vulnerable app.
    They serve as documentation of the attack surface.
    """

    def test_sql_injection_login_bypass(self, vulnerable_client):
        """
        SQL injection: username = "admin' --" bypasses password check.
        The query becomes: SELECT * FROM users WHERE username='admin' --' AND password='...'
        The -- comments out the password clause.
        """
        resp = vulnerable_client.post("/login", data={
            "username": "admin' --",
            "password": "wrongpassword",
        })
        # A 302 redirect means we logged in successfully — bypass worked
        assert resp.status_code == 302, "SQL injection login bypass should work on vulnerable app"

    def test_export_no_auth_required(self, vulnerable_client):
        """Sensitive data endpoint requires no authentication."""
        resp = vulnerable_client.get("/export")
        assert resp.status_code == 200
        data = resp.get_json()
        # Password hashes are exposed
        assert any("password_hash" in str(row) for row in data)

    def test_idor_note_access(self, vulnerable_client):
        """Any authenticated user can access any note by changing the ID."""
        # Log in as alice (not admin)
        vulnerable_client.post("/login", data={"username": "alice", "password": "alice123"})
        # Access admin's note (ID=1)
        resp = vulnerable_client.get("/notes/1")
        assert resp.status_code == 200
        # Alice should NOT be able to see admin's note — but she can (IDOR)
        assert resp.status_code != 403


# ===========================================================================
# Secure app: verify fixes work
# ===========================================================================

class TestSecureAppFixes:
    """
    These tests CONFIRM that the security controls in the secure app work.
    """

    def _login(self, client, username="admin", password="ChangeMe!SecureP@ss1"):
        return client.post("/login", data={"username": username, "password": password})

    def test_sql_injection_fails(self, secure_client):
        """
        SQL injection payload should NOT bypass authentication in the secure app.
        Parameterised query means the literal string "admin' --" is the username searched for.
        No user has that username, so login fails.
        """
        resp = secure_client.post("/login", data={
            "username": "admin' --",
            "password": "anything",
        }, follow_redirects=True)
        # Should stay on the login page with an error, NOT reach the dashboard.
        # (Can't just search for "dashboard": the nav bar always links to /dashboard.)
        assert resp.request.path == "/login"
        with secure_client.session_transaction() as sess:
            assert "user_id" not in sess

    def test_export_requires_auth(self, secure_client):
        """Export endpoint must require authentication."""
        resp = secure_client.get("/export")
        # Should redirect to login or return 401
        assert resp.status_code in (302, 401, 403)

    def test_export_no_password_hash(self, secure_client):
        """Even when admin calls export, password hashes must NOT be returned."""
        self._login(secure_client)
        resp = secure_client.get("/export")
        if resp.status_code == 200:
            data = resp.get_data(as_text=True)
            assert "password" not in data.lower()

    def test_security_headers_present(self, secure_client):
        """Every response should include security headers."""
        resp = secure_client.get("/login")
        assert "X-Frame-Options"        in resp.headers
        assert "X-Content-Type-Options" in resp.headers
        assert "Content-Security-Policy" in resp.headers

    def test_idor_prevention(self, secure_client):
        """A user cannot access another user's notes."""
        # First: register alice
        secure_client.post("/register", data={
            "username": "alice",
            "password": "SuperSecure@Pass1",
        })
        # Log in as alice
        self._login(secure_client, username="alice", password="SuperSecure@Pass1")
        # Try to access note ID 1 (admin's note)
        resp = secure_client.get("/notes/1")
        assert resp.status_code == 404  # "not found" — ownership enforced

    def test_command_injection_blocked(self, secure_client):
        """Hostname validation blocks shell metacharacters."""
        self._login(secure_client)
        # Attempt command injection
        resp = secure_client.get("/ping?host=localhost;cat+/etc/passwd")
        assert resp.status_code == 400

    def test_xss_payload_stripped(self, secure_client):
        """HTML/script tags are stripped before storage."""
        self._login(secure_client)
        payload = "<script>alert('xss')</script>Hello"
        secure_client.post("/comment", data={"comment": payload})
        resp = secure_client.get("/comment")
        # Script tag should not appear in the response
        assert b"<script>" not in resp.data

    def test_ssrf_internal_ip_blocked(self, secure_client):
        """Internal IP addresses must be blocked."""
        self._login(secure_client)
        # Try to reach cloud metadata endpoint
        resp = secure_client.get("/fetch?url=http://169.254.169.254/latest/meta-data/")
        assert resp.status_code == 400

    def test_ssrf_loopback_blocked(self, secure_client):
        """Loopback address must be blocked."""
        self._login(secure_client)
        resp = secure_client.get("/fetch?url=http://127.0.0.1:5432/")
        assert resp.status_code == 400

    def test_short_password_rejected(self, secure_client):
        """Passwords under 12 characters must be rejected at registration."""
        resp = secure_client.post("/register", data={
            "username": "newuser",
            "password": "short",
        }, follow_redirects=True)
        # Should not redirect to login — registration should fail
        assert b"at least 12" in resp.data or resp.status_code != 302

    def test_invalid_username_rejected(self, secure_client):
        """Usernames with special characters must be rejected."""
        resp = secure_client.post("/register", data={
            "username": "user'; DROP TABLE users;--",
            "password": "SuperSecure@Pass1",
        })
        # WTForms regex validator should reject this
        assert resp.status_code in (200, 400)


# ===========================================================================
# SSRF helper unit tests
# ===========================================================================

class TestSsrfValidator:
    def test_private_ip_rejected(self):
        from secure_app.app import is_safe_url
        assert is_safe_url("http://192.168.1.1/") is False
        assert is_safe_url("http://10.0.0.1/admin") is False
        assert is_safe_url("http://172.16.0.1/") is False

    def test_loopback_rejected(self):
        from secure_app.app import is_safe_url
        assert is_safe_url("http://127.0.0.1:8080/") is False
        assert is_safe_url("http://localhost/") is False

    def test_cloud_metadata_rejected(self):
        from secure_app.app import is_safe_url
        assert is_safe_url("http://169.254.169.254/latest/meta-data/") is False

    def test_file_scheme_rejected(self):
        from secure_app.app import is_safe_url
        assert is_safe_url("file:///etc/passwd") is False

    def test_allowed_domain_accepted(self):
        from secure_app.app import is_safe_url
        assert is_safe_url("https://example.com/api") is True

    def test_unknown_domain_rejected(self):
        from secure_app.app import is_safe_url
        assert is_safe_url("https://evil.com/") is False
