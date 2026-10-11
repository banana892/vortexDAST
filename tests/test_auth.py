"""Tests for authenticated-scanning scaffold (core/auth.py + Requester recovery)."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from core.auth import FormLoginAuthenticator, parse_login_data
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
