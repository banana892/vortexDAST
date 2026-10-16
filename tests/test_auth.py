"""Tests for authenticated-scanning scaffold (core/auth.py + Requester recovery)."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from core.auth import (
    FormLoginAuthenticator,
    OAuth2Authenticator,
    _pkce_pair,
    parse_login_data,
    totp,
)
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


# ── OAuth2/OIDC ────────────────────────────────────────────────────────────────


class _OAuth2Server:
    """
    POST /token:
      grant_type=client_credentials (client_id/client_secret=cid/csecret)
      grant_type=password (username/password=bob/pw)
      grant_type=refresh_token (refresh_token=<last issued>)
      -> 200 {"access_token": ..., "expires_in": N, "refresh_token": ...}
         (a successful grant invalidates any previously issued access token,
         so /protected proves which token is actually current)
      -> 400 on a credential mismatch
    GET /protected (needs "Authorization: Bearer <current access_token>"):
      -> 200 "protected area" / 401 "unauthorized"
    """

    def __init__(self) -> None:
        self.current_access_token: str | None = None
        self.current_refresh_token: str | None = None
        self.grant_counts: dict[str, int] = {}
        self._lock = threading.Lock()
        server = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _json(self, code, payload):
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                if urlsplit(self.path).path != "/token":
                    self.send_response(404)
                    self.end_headers()
                    return
                n = int(self.headers.get("Content-Length") or 0)
                form = parse_qs(self.rfile.read(n).decode())
                grant = (form.get("grant_type") or [None])[0]
                with server._lock:
                    server.grant_counts[grant] = server.grant_counts.get(grant, 0) + 1

                    ok = False
                    if grant == "client_credentials":
                        ok = (
                            form.get("client_id") == ["cid"]
                            and form.get("client_secret") == ["csecret"]
                        )
                    elif grant == "password":
                        ok = (
                            form.get("username") == ["bob"]
                            and form.get("password") == ["pw"]
                        )
                    elif grant == "refresh_token":
                        ok = (form.get("refresh_token") or [None])[0] == server.current_refresh_token

                    if not ok:
                        self._json(400, {"error": "invalid_grant"})
                        return

                    server.current_access_token = secrets.token_hex(8)
                    server.current_refresh_token = secrets.token_hex(8)
                    self._json(
                        200,
                        {
                            "access_token": server.current_access_token,
                            "expires_in": 3600,
                            "refresh_token": server.current_refresh_token,
                        },
                    )

            def do_GET(self):
                if urlsplit(self.path).path != "/protected":
                    self.send_response(404)
                    self.end_headers()
                    return
                sent = self.headers.get("Authorization", "")
                with server._lock:
                    valid = server.current_access_token is not None and sent == f"Bearer {server.current_access_token}"
                if valid:
                    self._json(200, {"ok": True, "body": "protected area"})
                else:
                    self._json(401, {"error": "unauthorized"})

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
def oauth2_server():
    s = _OAuth2Server()
    try:
        yield s
    finally:
        s.close()


def test_oauth2_client_credentials_login_sets_bearer_and_unlocks_resource(oauth2_server):
    req = _requester()
    try:
        auth = OAuth2Authenticator(
            token_url=f"{oauth2_server.base}/token",
            grant_type="client_credentials",
            client_id="cid",
            client_secret="csecret",
        )
        assert auth.login(req) is True
        assert req.session.headers["Authorization"] == f"Bearer {oauth2_server.current_access_token}"
        resp, err = req.get(f"{oauth2_server.base}/protected")
        assert err is None
        assert "protected area" in resp.text
    finally:
        req.close()


def test_oauth2_password_grant_login_succeeds(oauth2_server):
    req = _requester()
    try:
        auth = OAuth2Authenticator(
            token_url=f"{oauth2_server.base}/token",
            grant_type="password",
            client_id="cid",
            username="bob",
            password="pw",
        )
        assert auth.login(req) is True
        resp, _ = req.get(f"{oauth2_server.base}/protected")
        assert "protected area" in resp.text
    finally:
        req.close()


def test_oauth2_wrong_client_secret_login_fails(oauth2_server):
    req = _requester()
    try:
        auth = OAuth2Authenticator(
            token_url=f"{oauth2_server.base}/token",
            grant_type="client_credentials",
            client_id="cid",
            client_secret="WRONG",
        )
        assert auth.login(req) is False
    finally:
        req.close()


def test_oauth2_invalid_grant_type_rejected():
    with pytest.raises(ValueError):
        OAuth2Authenticator(
            token_url="https://example.test/token",
            grant_type="implicit",
            client_id="cid",
        )


def test_oauth2_authorization_code_requires_authorize_url_redirect_uri_and_login_data():
    with pytest.raises(ValueError):
        OAuth2Authenticator(
            token_url="https://example.test/token",
            grant_type="authorization_code",
            client_id="cid",
        )


def test_oauth2_password_grant_requires_username_and_password():
    with pytest.raises(ValueError):
        OAuth2Authenticator(
            token_url="https://example.test/token",
            grant_type="password",
            client_id="cid",
        )


def test_oauth2_unauthorized_response_marks_session_invalid(oauth2_server):
    req = _requester()
    try:
        auth = OAuth2Authenticator(
            token_url=f"{oauth2_server.base}/token",
            grant_type="client_credentials",
            client_id="cid",
            client_secret="csecret",
        )
        auth.login(req)
        # Corrupt the session's own bearer token, bypassing the authenticator,
        # to simulate the resource server rejecting it.
        req.session.headers["Authorization"] = "Bearer stale-or-revoked"
        resp, _ = req.get(f"{oauth2_server.base}/protected")
        assert resp.status_code == 401
        assert auth.is_session_valid(resp) is False
    finally:
        req.close()


def test_oauth2_session_recovery_refreshes_via_refresh_token(oauth2_server):
    req = _requester()
    try:
        auth = OAuth2Authenticator(
            token_url=f"{oauth2_server.base}/token",
            grant_type="client_credentials",
            client_id="cid",
            client_secret="csecret",
        )
        assert auth.login(req) is True
        req.set_session_recovery(auth.is_session_valid, lambda: auth.reauthenticate(req))

        # Simulate expiry/rejection the way a real deployment would surface it.
        req.session.headers["Authorization"] = "Bearer stale-or-revoked"
        resp, err = req.get(f"{oauth2_server.base}/protected")

        assert err is None
        assert "protected area" in resp.text  # transparently recovered
        assert oauth2_server.grant_counts.get("refresh_token") == 1
        assert oauth2_server.grant_counts.get("client_credentials") == 1  # not re-run
    finally:
        req.close()


# ── authorization_code + PKCE (real headless Chromium) ────────────────────────
#
# Playwright + Chromium are a core dependency (same as tests/test_dom_watcher.py),
# so this drives a *real* headless browser through a fake IdP's login page —
# the actual interactive redirect this grant exists to automate, not a mock of it.


def test_pkce_pair_challenge_matches_verifier():
    verifier, challenge = _pkce_pair()
    assert 43 <= len(verifier) <= 128
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    assert challenge == expected
    assert "=" not in challenge  # unpadded, URL-safe per RFC 7636


class _AuthCodeServer:
    """
    Minimal OAuth2 authorization_code + PKCE identity provider:
      GET  /authorize?response_type=code&client_id=...&redirect_uri=...&state=...
           &code_challenge=...&code_challenge_method=S256
           -> an HTML login form (inputs: user, pass) carrying the above as
              hidden fields so the POST below can see them.
      POST /authorize (user, pass, + the hidden fields)
           -> wrong creds: 200 "Invalid credentials" (no redirect)
           -> right creds, mfa_secret unset: 302 Location:
              <redirect_uri>?code=<code>&state=<state> (code is single-use,
              bound to the code_challenge that minted it)
           -> right creds, mfa_secret set: 302 Location: /mfa?... (carrying
              redirect_uri/state/code_challenge forward as a query string)
              instead of issuing the code yet.
      GET  /mfa?redirect_uri=...&state=...&code_challenge=...
           -> an HTML OTP form (input: otp) carrying the above forward as
              hidden fields, same shape as /authorize's own login form.
      POST /mfa (otp, + the hidden fields)
           -> wrong/missing otp: 200 "Invalid code" (no redirect)
           -> otp == totp(mfa_secret): same code-issuing redirect /authorize
              would have sent directly, had mfa_secret been unset.
      POST /token (grant_type=authorization_code|refresh_token, ...)
           -> authorization_code: verifies sha256(code_verifier) (b64url,
              unpadded) matches the stored code_challenge and the code hasn't
              already been redeemed.
    """

    def __init__(self, mfa_secret: "str | None" = None, js_redirect: bool = False) -> None:
        self._lock = threading.Lock()
        self._codes: dict[str, dict] = {}
        self.current_access_token: str | None = None
        self.current_refresh_token: str | None = None
        self.grant_counts: dict[str, int] = {}
        self.authorize_hits = 0
        self.mfa_hits = 0
        self.mfa_secret = mfa_secret
        self.js_redirect = js_redirect
        server = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _send(self, code, body):
                data = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _json(self, code, payload):
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _issue_code(self, redirect_uri, state, challenge):
                """Mint a single-use code and send the browser to redirect_uri
                with it — the final step whether it's reached straight from
                /authorize (no MFA configured) or from /mfa (MFA verified).
                Delivered either as an HTTP 3xx Location redirect, or — when
                server.js_redirect is set — as a 200 HTML page that navigates
                there via JS, the client-side shape some real IdPs use."""
                code = secrets.token_hex(8)
                with server._lock:
                    server._codes[code] = {
                        "challenge": challenge,
                        "redirect_uri": redirect_uri,
                        "used": False,
                    }
                sep = "&" if "?" in (redirect_uri or "") else "?"
                location = f"{redirect_uri}{sep}code={code}&state={state}"
                if server.js_redirect:
                    self._send(200, f'<html><body><script>window.location = "{location}";</script></body></html>')
                    return
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                if urlsplit(self.path).path == "/authorize":
                    with server._lock:
                        server.authorize_hits += 1
                    qs = parse_qs(urlsplit(self.path).query)
                    hidden = "".join(
                        f'<input type="hidden" name="{k}" value="{v[0]}">'
                        for k, v in qs.items()
                    )
                    self._send(
                        200,
                        f'<html><body><form method="post" action="/authorize">{hidden}'
                        '<input name="user"><input name="pass" type="password">'
                        '<button type="submit">Log in</button>'
                        "</form></body></html>",
                    )
                    return
                if urlsplit(self.path).path == "/mfa":
                    qs = parse_qs(urlsplit(self.path).query)
                    hidden = "".join(
                        f'<input type="hidden" name="{k}" value="{v[0]}">'
                        for k, v in qs.items()
                    )
                    self._send(
                        200,
                        f'<html><body><form method="post" action="/mfa">{hidden}'
                        '<input name="otp"><button type="submit">Verify</button>'
                        "</form></body></html>",
                    )
                    return
                if urlsplit(self.path).path == "/callback":
                    # The code is read from the redirect's Location header before this
                    # is even dispatched; the browser may still land here afterward.
                    self._send(200, "callback reached")
                    return
                self._send(404, "nope")

            def do_POST(self):
                path = urlsplit(self.path).path
                n = int(self.headers.get("Content-Length") or 0)
                form = parse_qs(self.rfile.read(n).decode())

                if path == "/authorize":
                    user = (form.get("user") or [None])[0]
                    pw = (form.get("pass") or [None])[0]
                    redirect_uri = (form.get("redirect_uri") or [None])[0]
                    state = (form.get("state") or [""])[0]
                    challenge = (form.get("code_challenge") or [None])[0]
                    if user != "admin" or pw != "pw":
                        self._send(200, "Invalid credentials")
                        return
                    if server.mfa_secret:
                        mfa_qs = urlencode(
                            {"redirect_uri": redirect_uri, "state": state, "code_challenge": challenge}
                        )
                        self.send_response(302)
                        self.send_header("Location", f"/mfa?{mfa_qs}")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    self._issue_code(redirect_uri, state, challenge)
                    return

                if path == "/mfa":
                    with server._lock:
                        server.mfa_hits += 1
                    otp = (form.get("otp") or [None])[0]
                    redirect_uri = (form.get("redirect_uri") or [None])[0]
                    state = (form.get("state") or [""])[0]
                    challenge = (form.get("code_challenge") or [None])[0]
                    if not server.mfa_secret or otp != totp(server.mfa_secret):
                        self._send(200, "Invalid code")
                        return
                    self._issue_code(redirect_uri, state, challenge)
                    return

                if path == "/token":
                    grant = (form.get("grant_type") or [None])[0]
                    with server._lock:
                        server.grant_counts[grant] = server.grant_counts.get(grant, 0) + 1
                        ok = False
                        if grant == "authorization_code":
                            code = (form.get("code") or [None])[0]
                            verifier = (form.get("code_verifier") or [None])[0]
                            entry = server._codes.get(code)
                            if entry and not entry["used"] and verifier:
                                digest = hashlib.sha256(verifier.encode()).digest()
                                expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                                ok = expected == entry["challenge"]
                            if ok:
                                entry["used"] = True
                        elif grant == "refresh_token":
                            ok = (form.get("refresh_token") or [None])[0] == server.current_refresh_token
                        if not ok:
                            self._json(400, {"error": "invalid_grant"})
                            return
                        server.current_access_token = secrets.token_hex(8)
                        server.current_refresh_token = secrets.token_hex(8)
                        self._json(
                            200,
                            {
                                "access_token": server.current_access_token,
                                "expires_in": 3600,
                                "refresh_token": server.current_refresh_token,
                            },
                        )
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
def authcode_server():
    s = _AuthCodeServer()
    try:
        yield s
    finally:
        s.close()


_AUTHCODE_TIMEOUT_MS = 3000


def test_oauth2_authorization_code_pkce_full_flow(authcode_server):
    req = _requester()
    try:
        auth = OAuth2Authenticator(
            token_url=f"{authcode_server.base}/token",
            grant_type="authorization_code",
            client_id="cid",
            authorize_url=f"{authcode_server.base}/authorize",
            redirect_uri=f"{authcode_server.base}/callback",
            login_credentials={"user": "admin", "pass": "pw"},
            nav_timeout_ms=_AUTHCODE_TIMEOUT_MS,
        )
        assert auth.login(req) is True
        assert req.session.headers["Authorization"] == f"Bearer {authcode_server.current_access_token}"
        assert authcode_server.grant_counts.get("authorization_code") == 1
        assert authcode_server.authorize_hits == 1
    finally:
        req.close()


def test_oauth2_authorization_code_client_side_redirect():
    """Some IdPs hand back the code via a client-side (JS) redirect instead
    of an HTTP 3xx Location header — the code must still be captured."""
    server = _AuthCodeServer(js_redirect=True)
    req = _requester()
    try:
        auth = OAuth2Authenticator(
            token_url=f"{server.base}/token",
            grant_type="authorization_code",
            client_id="cid",
            authorize_url=f"{server.base}/authorize",
            redirect_uri=f"{server.base}/callback",
            login_credentials={"user": "admin", "pass": "pw"},
            nav_timeout_ms=_AUTHCODE_TIMEOUT_MS,
        )
        assert auth.login(req) is True
        assert req.session.headers["Authorization"] == f"Bearer {server.current_access_token}"
        assert server.grant_counts.get("authorization_code") == 1
    finally:
        req.close()
        server.close()


def test_oauth2_authorization_code_wrong_credentials_fails(authcode_server):
    req = _requester()
    try:
        auth = OAuth2Authenticator(
            token_url=f"{authcode_server.base}/token",
            grant_type="authorization_code",
            client_id="cid",
            authorize_url=f"{authcode_server.base}/authorize",
            redirect_uri=f"{authcode_server.base}/callback",
            login_credentials={"user": "admin", "pass": "WRONG"},
            nav_timeout_ms=_AUTHCODE_TIMEOUT_MS,
        )
        assert auth.login(req) is False
        assert "Authorization" not in req.session.headers
    finally:
        req.close()


def test_oauth2_authorization_code_reused_code_is_rejected(authcode_server):
    """A code redeemed once can't be redeemed again (single-use, per RFC 6749 §4.1.2)."""
    req = _requester()
    try:
        auth = OAuth2Authenticator(
            token_url=f"{authcode_server.base}/token",
            grant_type="authorization_code",
            client_id="cid",
            authorize_url=f"{authcode_server.base}/authorize",
            redirect_uri=f"{authcode_server.base}/callback",
            login_credentials={"user": "admin", "pass": "pw"},
            nav_timeout_ms=_AUTHCODE_TIMEOUT_MS,
        )
        assert auth.login(req) is True
        # Replay the same code/verifier straight at the token endpoint.
        last_code = next(iter(authcode_server._codes))
        resp, _ = req.post(
            f"{authcode_server.base}/token",
            data={
                "grant_type": "authorization_code",
                "code": last_code,
                "client_id": "cid",
                "redirect_uri": f"{authcode_server.base}/callback",
                "code_verifier": "replayed-does-not-matter-already-used",
            },
        )
        assert resp.status_code == 400
    finally:
        req.close()


def test_oauth2_authorization_code_reauthenticate_without_refresh_token_redoes_browser_login(
    authcode_server,
):
    req = _requester()
    try:
        auth = OAuth2Authenticator(
            token_url=f"{authcode_server.base}/token",
            grant_type="authorization_code",
            client_id="cid",
            authorize_url=f"{authcode_server.base}/authorize",
            redirect_uri=f"{authcode_server.base}/callback",
            login_credentials={"user": "admin", "pass": "pw"},
            nav_timeout_ms=_AUTHCODE_TIMEOUT_MS,
        )
        assert auth.login(req) is True
        first_token = authcode_server.current_access_token
        auth._refresh_token = None  # simulate no refresh token ever issued
        assert auth.reauthenticate(req) is True
        assert authcode_server.grant_counts.get("authorization_code") == 2
        assert authcode_server.authorize_hits == 2
        assert req.session.headers["Authorization"] == f"Bearer {authcode_server.current_access_token}"
        assert authcode_server.current_access_token != first_token
    finally:
        req.close()


# ── authorization_code + PKCE, with an MFA step ───────────────────────────────
#
# Same fake IdP, but one that renders an OTP page between accepting the
# primary login and issuing the code — the shape a real MFA-protected IdP
# login flow takes. Exercises OAuth2Authenticator._submit_mfa_step.


@pytest.fixture
def authcode_server_with_mfa():
    secret = base64.b32encode(secrets.token_bytes(10)).decode()
    s = _AuthCodeServer(mfa_secret=secret)
    s.mfa_secret_b32 = secret  # convenience for tests building the {totp:...} field
    try:
        yield s
    finally:
        s.close()


def test_oauth2_authorization_code_mfa_step_succeeds(authcode_server_with_mfa):
    server = authcode_server_with_mfa
    req = _requester()
    try:
        auth = OAuth2Authenticator(
            token_url=f"{server.base}/token",
            grant_type="authorization_code",
            client_id="cid",
            authorize_url=f"{server.base}/authorize",
            redirect_uri=f"{server.base}/callback",
            login_credentials={"user": "admin", "pass": "pw"},
            mfa_data={"otp": f"{{totp:{server.mfa_secret_b32}}}"},
            nav_timeout_ms=_AUTHCODE_TIMEOUT_MS,
        )
        assert auth.login(req) is True
        assert req.session.headers["Authorization"] == f"Bearer {server.current_access_token}"
        assert server.mfa_hits == 1
    finally:
        req.close()


def test_oauth2_authorization_code_without_mfa_data_fails_against_mfa_idp(authcode_server_with_mfa):
    """The IdP requires MFA but mfa_data isn't configured — the flow degrades to
    'no code', not a hang or a crash, same contract as a rejected primary login."""
    server = authcode_server_with_mfa
    req = _requester()
    try:
        auth = OAuth2Authenticator(
            token_url=f"{server.base}/token",
            grant_type="authorization_code",
            client_id="cid",
            authorize_url=f"{server.base}/authorize",
            redirect_uri=f"{server.base}/callback",
            login_credentials={"user": "admin", "pass": "pw"},
            nav_timeout_ms=_AUTHCODE_TIMEOUT_MS,
        )
        assert auth.login(req) is False
        assert "Authorization" not in req.session.headers
        assert server.mfa_hits == 0  # never even attempted — no mfa_data to submit
    finally:
        req.close()


def test_oauth2_authorization_code_mfa_data_is_noop_when_not_needed(authcode_server):
    """mfa_data configured against an IdP that never asks for it: _submit_mfa_step
    must see the code already arrived and skip, not error on a missing selector."""
    req = _requester()
    try:
        auth = OAuth2Authenticator(
            token_url=f"{authcode_server.base}/token",
            grant_type="authorization_code",
            client_id="cid",
            authorize_url=f"{authcode_server.base}/authorize",
            redirect_uri=f"{authcode_server.base}/callback",
            login_credentials={"user": "admin", "pass": "pw"},
            mfa_data={"otp": "000000"},
            nav_timeout_ms=_AUTHCODE_TIMEOUT_MS,
        )
        assert auth.login(req) is True
        assert req.session.headers["Authorization"] == f"Bearer {authcode_server.current_access_token}"
        assert authcode_server.mfa_hits == 0
    finally:
        req.close()


# ── OAuth2 role matrix (two independent identities) ────────────────────────
#
# scanner.py's --role2-oauth2-* wiring authenticates a *second*
# OAuth2Authenticator (its own client_id/secret, username/password, or IdP
# login) into its own Requester, then hands that session to
# access_control_check.set_role_requester() — exactly the mechanism this
# test exercises directly, independent of scanner.py's argument plumbing
# (which has no CLI-level test harness in this suite; see core/auth.py's own
# unit tests above for each grant individually).


class _RoleMatrixOAuth2Server:
    """
    A client_credentials IdP with two distinct registered clients, each
    minted its own independently valid token:
      POST /token (client_id/client_secret: "admin-svc"/"adminsecret" or
                   "user-svc"/"usersecret") -> {access_token, expires_in}
      GET  /admin-only (Bearer <admin-svc's token>) -> 200 "admin area"
                                                     -> 401 otherwise
    """

    _CLIENTS = {"admin-svc": "adminsecret", "user-svc": "usersecret"}

    def __init__(self) -> None:
        self._tokens: dict[str, str] = {}  # token -> client_id
        server = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _json(self, code, payload):
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                if urlsplit(self.path).path != "/token":
                    self.send_response(404)
                    self.end_headers()
                    return
                n = int(self.headers.get("Content-Length") or 0)
                form = parse_qs(self.rfile.read(n).decode())
                cid = (form.get("client_id") or [None])[0]
                secret = (form.get("client_secret") or [None])[0]
                if server._CLIENTS.get(cid) != secret:
                    self._json(400, {"error": "invalid_client"})
                    return
                token = secrets.token_hex(8)
                server._tokens[token] = cid
                self._json(200, {"access_token": token, "expires_in": 3600})

            def do_GET(self):
                if urlsplit(self.path).path != "/admin-only":
                    self.send_response(404)
                    self.end_headers()
                    return
                auth_header = self.headers.get("Authorization", "")
                token = auth_header[len("Bearer "):] if auth_header.startswith("Bearer ") else None
                if server._tokens.get(token) == "admin-svc":
                    self._json(200, {"body": "admin area"})
                else:
                    self._json(401, {"error": "unauthorized"})

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
def role_matrix_oauth2_server():
    s = _RoleMatrixOAuth2Server()
    try:
        yield s
    finally:
        s.close()


def test_oauth2_role_matrix_two_identities_get_independent_sessions(role_matrix_oauth2_server):
    base = role_matrix_oauth2_server.base
    primary_req = _requester()
    role_req = _requester()
    try:
        primary = OAuth2Authenticator(
            token_url=f"{base}/token",
            grant_type="client_credentials",
            client_id="admin-svc",
            client_secret="adminsecret",
        )
        role2 = OAuth2Authenticator(
            token_url=f"{base}/token",
            grant_type="client_credentials",
            client_id="user-svc",
            client_secret="usersecret",
        )
        assert primary.login(primary_req) is True
        assert role2.login(role_req) is True

        # Distinct bearer tokens, each attached to its own session — the two
        # identities never share state despite hitting the same token_url.
        assert (
            primary_req.session.headers["Authorization"]
            != role_req.session.headers["Authorization"]
        )

        resp_primary, _ = primary_req.get(f"{base}/admin-only")
        resp_role2, _ = role_req.get(f"{base}/admin-only")
        assert resp_primary.status_code == 200
        # The exact access-control diff a role matrix exists to surface.
        assert resp_role2.status_code == 401
    finally:
        primary_req.close()
        role_req.close()
