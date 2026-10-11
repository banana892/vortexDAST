"""Tests for authenticated-scanning scaffold (core/auth.py + Requester recovery)."""

from __future__ import annotations

import base64
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from core.auth import FormLoginAuthenticator, parse_login_data, totp
from core.requester import Requester


# ── parse_login_data ──────────────────────────────────────────────────────────


def test_parse_login_data_basic():
    assert parse_login_data("username=admin&password=secret") == {
        "username": "admin",
        "password": "secret",
    }


def test_parse_login_data_value_with_equals():
    assert parse_login_data("token=a=b=c") == {"token": "a=b=c"}


def test_parse_login_data_rejects_empty():
    with pytest.raises(ValueError):
        parse_login_data("")


def test_parse_login_data_rejects_missing_eq():
    with pytest.raises(ValueError):
        parse_login_data("usernameadmin")


# ── Live login server ──────────────────────────────────────────────────────────


class _AuthServer:
    """
    Minimal session-cookie app:
      POST /login (user=admin&pass=pw) -> 200 + Set-Cookie: SID=good, body "Sign out"
      GET  /secret with cookie SID=good -> 200 "secret area"
      GET  /secret without it           -> 200 "Please log in"
    Tracks how many successful logins happened (to assert re-auth).
    """

    def __init__(self) -> None:
        self.logins = 0
        self._lock = threading.Lock()
        server = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _send(self, code, body, cookie=None):
                data = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                if cookie:
                    self.send_header("Set-Cookie", cookie)
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                if urlsplit(self.path).path == "/login":
                    n = int(self.headers.get("Content-Length") or 0)
                    form = parse_qs(self.rfile.read(n).decode())
                    if form.get("user") == ["admin"] and form.get("pass") == ["pw"]:
                        with server._lock:
                            server.logins += 1
                        self._send(200, "Welcome. Sign out", cookie="SID=good; Path=/")
                    else:
                        self._send(200, "Invalid credentials")
                    return
                self._send(404, "nope")

            def do_GET(self):
                if urlsplit(self.path).path == "/secret":
                    if "SID=good" in self.headers.get("Cookie", ""):
                        self._send(200, "secret area")
                    else:
                        self._send(200, "Please log in")
                    return
                self._send(404, "nope")

            def log_message(self, *a):
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self._httpd.shutdown()


@pytest.fixture
def auth_server():
    s = _AuthServer()
    try:
        yield s
    finally:
        s.close()


def _requester():
    return Requester(rate_limit_rps=0, max_retries=0)


# ── Login ───────────────────────────────────────────────────────────────────


def test_login_success_sets_cookie(auth_server):
    req = _requester()
    try:
        auth = FormLoginAuthenticator(
            login_url=f"{auth_server.base}/login",
            credentials={"user": "admin", "pass": "pw"},
            success_text="Sign out",
        )
        assert auth.login(req) is True
        assert any(c.name == "SID" for c in req.session.cookies)
        # Session now authenticated for later requests.
        resp, _ = req.get(f"{auth_server.base}/secret")
        assert "secret area" in resp.text
    finally:
        req.close()


def test_login_failure_wrong_password(auth_server):
    req = _requester()
    try:
        auth = FormLoginAuthenticator(
            login_url=f"{auth_server.base}/login",
            credentials={"user": "admin", "pass": "WRONG"},
            success_text="Sign out",
            failure_text="Invalid credentials",
        )
        assert auth.login(req) is False
    finally:
        req.close()


# ── Session-loss detection + recovery ─────────────────────────────────────────


def test_is_session_valid_detects_logged_out(auth_server):
    req = _requester()
    try:
        auth = FormLoginAuthenticator(
            login_url=f"{auth_server.base}/login",
            credentials={"user": "admin", "pass": "pw"},
            logged_out_text="Please log in",
        )
        # Not logged in yet → /secret says "Please log in".
        resp, _ = req.get(f"{auth_server.base}/secret")
        assert auth.is_session_valid(resp) is False
        # After login → valid.
        auth.login(req)
        resp2, _ = req.get(f"{auth_server.base}/secret")
        assert auth.is_session_valid(resp2) is True
    finally:
        req.close()


def test_session_recovery_replays_after_reauth(auth_server):
    req = _requester()
    try:
        auth = FormLoginAuthenticator(
            login_url=f"{auth_server.base}/login",
            credentials={"user": "admin", "pass": "pw"},
            logged_out_text="Please log in",
        )
        req.set_session_recovery(
            auth.is_session_valid,
            lambda: auth.reauthenticate(req),
        )
        # First request has no session → validator fails → recovery logs in and
        # replays, so the caller transparently gets the authenticated page.
        resp, err = req.get(f"{auth_server.base}/secret")
        assert err is None
        assert "secret area" in resp.text
        assert auth_server.logins == 1
    finally:
        req.close()


def test_recovery_noop_without_hook(auth_server):
    req = _requester()
    try:
        # No set_session_recovery → logged-out response passes through unchanged.
        resp, err = req.get(f"{auth_server.base}/secret")
        assert err is None
        assert "Please log in" in resp.text
    finally:
        req.close()


# ── TOTP (RFC 6238) ────────────────────────────────────────────────────────────


def test_totp_matches_rfc6238_sha1_vectors():
    # RFC 6238 Appendix B's seed is the raw ASCII string "12345678901234567890";
    # our totp() takes a base32 secret (the "scan this QR code" form), so we
    # base32-encode that seed once and check the published 8-digit codes.
    seed_b32 = base64.b32encode(b"12345678901234567890").decode()
    assert totp(seed_b32, digits=8, when=59) == "94287082"
    assert totp(seed_b32, digits=8, when=1111111109) == "07081804"
    assert totp(seed_b32, digits=8, when=1111111111) == "14050471"


def test_totp_tolerates_spaces_and_lowercase_and_missing_padding():
    seed_b32 = base64.b32encode(b"12345678901234567890").decode()
    spaced = " ".join(seed_b32[i : i + 4] for i in range(0, len(seed_b32), 4)).lower()
    assert totp(spaced, digits=8, when=59) == totp(seed_b32, digits=8, when=59)


def test_totp_default_is_six_digits_and_changes_with_time():
    secret = base64.b32encode(secrets.token_bytes(10)).decode()
    code_a = totp(secret, when=1000.0)
    code_b = totp(secret, when=1000.0 + 30.0)  # next 30s window
    assert len(code_a) == 6 and code_a.isdigit()
    assert code_a != code_b


# ── CSRF-token harvesting ──────────────────────────────────────────────────────


class _CsrfLoginServer:
    """
    GET  /login            -> HTML with a fresh hidden csrf_token + login form
    POST /login (user/pass + the *exact* just-issued csrf_token)
                            -> 200 "Sign out" + Set-Cookie SID=good
                            -> 403 "bad csrf" if the token doesn't match
    """

    def __init__(self) -> None:
        # Pretend a token was already issued from an earlier page view, so a
        # submission that skips harvesting entirely (and so omits the field)
        # genuinely mismatches instead of "matching" two unset Nones.
        self.last_issued_token: str | None = secrets.token_hex(8)
        self.submitted_tokens: list[str | None] = []
        server = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _send(self, code, body, cookie=None):
                data = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                if cookie:
                    self.send_header("Set-Cookie", cookie)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if urlsplit(self.path).path == "/login":
                    server.last_issued_token = secrets.token_hex(8)
                    self._send(
                        200,
                        '<html><body><form method="post" action="/login">'
                        '<input type="hidden" name="csrf_token" '
                        f'value="{server.last_issued_token}">'
                        '<input name="user"><input name="pass">'
                        "</form></body></html>",
                    )
                    return
                self._send(404, "nope")

            def do_POST(self):
                if urlsplit(self.path).path == "/login":
                    n = int(self.headers.get("Content-Length") or 0)
                    form = parse_qs(self.rfile.read(n).decode())
                    token = (form.get("csrf_token") or [None])[0]
                    server.submitted_tokens.append(token)
                    if token != server.last_issued_token:
                        self._send(403, "bad csrf")
                        return
                    if form.get("user") == ["admin"] and form.get("pass") == ["pw"]:
                        self._send(200, "Welcome. Sign out", cookie="SID=good; Path=/")
                    else:
                        self._send(200, "Invalid credentials")
                    return
                self._send(404, "nope")

            def log_message(self, *a):
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self._httpd.shutdown()


@pytest.fixture
def csrf_server():
    s = _CsrfLoginServer()
    try:
        yield s
    finally:
        s.close()


def test_harvests_csrf_token_and_login_succeeds(csrf_server):
    req = _requester()
    try:
        auth = FormLoginAuthenticator(
            login_url=f"{csrf_server.base}/login",
            credentials={"user": "admin", "pass": "pw"},
            success_text="Sign out",
        )
        assert auth.login(req) is True
        # The token actually submitted was the one the server just issued —
        # proof it was harvested, not guessed or omitted.
        assert csrf_server.submitted_tokens == [csrf_server.last_issued_token]
    finally:
        req.close()


def test_without_harvesting_csrf_login_is_rejected(csrf_server):
    req = _requester()
    try:
        auth = FormLoginAuthenticator(
            login_url=f"{csrf_server.base}/login",
            credentials={"user": "admin", "pass": "pw"},
            success_text="Sign out",
            harvest_hidden_fields=False,
        )
        assert auth.login(req) is False
    finally:
        req.close()


def test_explicit_credential_wins_over_harvested_same_name(csrf_server):
    """An explicitly configured field overrides a same-named harvested one."""
    req = _requester()
    try:
        auth = FormLoginAuthenticator(
            login_url=f"{csrf_server.base}/login",
            credentials={"user": "admin", "pass": "pw", "csrf_token": "attacker-supplied"},
        )
        auth.login(req)
        assert csrf_server.submitted_tokens == ["attacker-supplied"]
    finally:
        req.close()


# ── Multi-step login / MFA ──────────────────────────────────────────────────────


class _MfaServer:
    """
    POST /login (user/pass)      -> 200 "verify MFA" + Set-Cookie SID=good
    GET  /mfa  (needs SID=good)  -> HTML with hidden mfa_csrf + otp form
    POST /mfa  (needs SID=good, correct otp + mfa_csrf)
                                  -> 200 "Sign out" + Set-Cookie MFA=ok
    GET  /secret (needs SID=good AND MFA=ok) -> "secret area"
    """

    def __init__(self, totp_secret: str | None = None, static_code: str | None = None) -> None:
        self.totp_secret = totp_secret
        self.static_code = static_code
        self.last_mfa_csrf: str | None = None
        self.mfa_attempts = 0
        server = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _send(self, code, body, cookie=None):
                data = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                if cookie:
                    self.send_header("Set-Cookie", cookie)
                self.end_headers()
                self.wfile.write(data)

            def _cookie(self, name_eq_value):
                return name_eq_value in self.headers.get("Cookie", "")

            def do_GET(self):
                path = urlsplit(self.path).path
                if path == "/mfa" and self._cookie("SID=good"):
                    server.last_mfa_csrf = secrets.token_hex(8)
                    self._send(
                        200,
                        '<html><body><form method="post" action="/mfa">'
                        f'<input type="hidden" name="mfa_csrf" value="{server.last_mfa_csrf}">'
                        '<input name="otp"></form></body></html>',
                    )
                elif path == "/secret":
                    if self._cookie("SID=good") and self._cookie("MFA=ok"):
                        self._send(200, "secret area")
                    else:
                        self._send(200, "Please log in")
                else:
                    self._send(404, "nope")

            def do_POST(self):
                path = urlsplit(self.path).path
                n = int(self.headers.get("Content-Length") or 0)
                form = parse_qs(self.rfile.read(n).decode())

                if path == "/login":
                    if form.get("user") == ["admin"] and form.get("pass") == ["pw"]:
                        self._send(200, "verify MFA", cookie="SID=good; Path=/")
                    else:
                        self._send(200, "Invalid credentials")
                    return

                if path == "/mfa":
                    server.mfa_attempts += 1
                    otp = (form.get("otp") or [None])[0]
                    mfa_csrf = (form.get("mfa_csrf") or [None])[0]
                    expected = server.static_code or totp(server.totp_secret)
                    if (
                        self._cookie("SID=good")
                        and mfa_csrf == server.last_mfa_csrf
                        and otp == expected
                    ):
                        self._send(200, "Sign out", cookie="MFA=ok; Path=/")
                    else:
                        self._send(200, "Invalid code")
                    return

                self._send(404, "nope")

            def log_message(self, *a):
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self._httpd.shutdown()


def test_mfa_with_static_code_succeeds():
    server = _MfaServer(static_code="123456")
    req = _requester()
    try:
        auth = FormLoginAuthenticator(
            login_url=f"{server.base}/login",
            credentials={"user": "admin", "pass": "pw"},
            mfa_url=f"{server.base}/mfa",
            mfa_data={"otp": "123456"},
            mfa_success_text="Sign out",
        )
        assert auth.login(req) is True
        resp, _ = req.get(f"{server.base}/secret")
        assert "secret area" in resp.text
    finally:
        req.close()
        server.close()


def test_mfa_with_wrong_static_code_fails():
    server = _MfaServer(static_code="123456")
    req = _requester()
    try:
        auth = FormLoginAuthenticator(
            login_url=f"{server.base}/login",
            credentials={"user": "admin", "pass": "pw"},
            mfa_url=f"{server.base}/mfa",
            mfa_data={"otp": "000000"},
            mfa_success_text="Sign out",
        )
        assert auth.login(req) is False
    finally:
        req.close()
        server.close()


def test_mfa_with_live_totp_secret_succeeds():
    secret = base64.b32encode(secrets.token_bytes(10)).decode()
    server = _MfaServer(totp_secret=secret)
    req = _requester()
    try:
        auth = FormLoginAuthenticator(
            login_url=f"{server.base}/login",
            credentials={"user": "admin", "pass": "pw"},
            mfa_url=f"{server.base}/mfa",
            mfa_data={"otp": f"{{totp:{secret}}}"},
            mfa_success_text="Sign out",
        )
        assert auth.login(req) is True
    finally:
        req.close()
        server.close()


def test_reauthenticate_replays_both_steps_with_fresh_totp():
    secret = base64.b32encode(secrets.token_bytes(10)).decode()
    server = _MfaServer(totp_secret=secret)
    req = _requester()
    try:
        auth = FormLoginAuthenticator(
            login_url=f"{server.base}/login",
            credentials={"user": "admin", "pass": "pw"},
            logged_out_text="Please log in",
            mfa_url=f"{server.base}/mfa",
            mfa_data={"otp": f"{{totp:{secret}}}"},
            mfa_success_text="Sign out",
        )
        req.set_session_recovery(auth.is_session_valid, lambda: auth.reauthenticate(req))
        resp, err = req.get(f"{server.base}/secret")
        assert err is None
        assert "secret area" in resp.text
        assert server.mfa_attempts == 1
    finally:
        req.close()
        server.close()
