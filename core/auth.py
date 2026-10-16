"""
VortexDAST – core/auth.py
────────────────────────────────────────────────────────────────────────────
Authenticated-scanning scaffold.

The baseline :class:`~core.requester.Requester` only supports *static*
credentials (a fixed cookie, header, or HTTP basic/digest pair). That is
enough for token-authenticated APIs but not for the common case of a web app
that issues a session cookie from a login form and silently logs you out when
the session expires or a probe trips a security control.

This module adds the two missing pieces:

* :class:`FormLoginAuthenticator` — performs a form login against a configured
  URL, leaving the resulting session cookie(s) in the shared
  ``requests.Session`` so every subsequent scan request is authenticated.
* Session-loss detection + re-authentication — ``is_session_valid`` inspects a
  response for a "logged out" signal (a marker string, or a redirect to the
  login URL), and ``reauthenticate`` re-runs the login. Wiring this into
  :meth:`Requester._dispatch` (via ``Requester.set_session_recovery``) means a
  dropped session is transparently recovered mid-scan instead of quietly
  voiding every finding after the logout.
* CSRF-token harvesting — before submitting either step, the authenticator
  GETs that step's page and pulls hidden-input fields (the usual home for a
  per-session CSRF token) out of its login-shaped form via the same
  :class:`~core.parser.HTMLParser` the crawler uses, merging them underneath
  whatever fields were explicitly configured. Best-effort and silent: a page
  that needs no token behaves exactly as before.
* Multi-step login / MFA — an optional second step (``mfa_url`` + ``mfa_data``)
  submitted after a successful primary login. A field value of the form
  ``"{totp:BASE32SECRET}"`` is replaced with a live RFC 6238 TOTP code at
  submission time (and again on every re-authentication), so a true
  authenticator-app-backed MFA flow can be scanned unattended — a fixed code
  would simply expire. A plain fixed code (e.g. a backup code) works too.
* :class:`OAuth2Authenticator` — a second, independent strategy for targets
  protected by OAuth2/OIDC instead of a session cookie: exchanges credentials
  for a bearer access token at the authorization server's token endpoint and
  attaches it to every request. Implements ``password`` (Resource Owner
  Password Credentials, a test account's own username/password) and
  ``client_credentials`` (a service-level client id/secret, no end-user
  account) in a single unattended HTTP call, plus ``authorization_code`` +
  PKCE (RFC 7636) — the interactive grant, which drives a real headless
  Chromium (via Playwright, same engine as `core/dom_watcher.py`) through the
  authorization server's own login page, intercepts the browser's navigation
  back to the registered ``redirect_uri`` to pull the code out of the URL
  without ever needing that URI to resolve to anything real, optionally
  filling an MFA step the IdP's post-login redirect renders next (same
  ``mfa_data``/``{totp:SECRET}`` semantics as ``FormLoginAuthenticator``),
  and exchanges the code for a token with the PKCE verifier. All three
  grants support token refresh.
  Same ``login``/``is_session_valid``/``reauthenticate`` shape as
  :class:`FormLoginAuthenticator`, so it plugs into
  :meth:`Requester.set_session_recovery` the same way.

Scope of this scaffold
-----------------------
Form-based login (GET or POST), CSRF-token harvesting, two-step/MFA logins,
and all three OAuth2/OIDC grants (``password``, ``client_credentials``,
``authorization_code`` + PKCE, each including its own MFA step) are
implemented and tested. A multi-identity "role matrix" comparison is
implemented for both form login (`modules/access_control_check.py`,
`--role2-login-data`) and every OAuth2 grant (`--role2-oauth2-*`) — neither
drives an MFA step for the role-matrix second identity, since a second
account's MFA secret always differs per-account and there's no per-identity
MFA config to plug in yet.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import secrets
import struct
import time
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlsplit

from .parser import HTMLParser

if TYPE_CHECKING:  # avoid a runtime import cycle
    import requests

    from core.requester import Requester

logger = logging.getLogger("vortexdast")

#: Matches an MFA field value asking for a live TOTP code, e.g.
#: ``"{totp:JBSWY3DPEHPK3PXP}"``. Anything else is submitted verbatim.
_TOTP_PLACEHOLDER = re.compile(r"^\{totp:([A-Za-z2-7 ]+=*)\}$")


def totp(secret_b32: str, *, digits: int = 6, period: int = 30, when: Optional[float] = None) -> str:
    """
    Compute an RFC 6238 time-based one-time code (the standard behind
    authenticator-app MFA) from a base32 secret.

    Parameters
    ----------
    secret_b32:
        The base32 secret as shown by a "scan this QR code" MFA enrolment
        screen (padding and spaces are tolerated).
    digits:
        Code length (RFC default, and what almost every app expects, is 6).
    period:
        Time-step in seconds (RFC default, near-universal in practice, is 30).
    when:
        Unix timestamp to compute for; defaults to now. Exposed for testing
        against RFC 6238's published vectors.

    Verified against the RFC 6238 Appendix B SHA-1 test vectors.
    """
    cleaned = secret_b32.strip().replace(" ", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)  # base32 requires a multiple-of-8 length
    key = base64.b32decode(cleaned)
    counter = int((when if when is not None else time.time()) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


class FormLoginAuthenticator:
    """
    Authenticate a scan session by submitting an HTML login form.

    Parameters
    ----------
    login_url:
        URL the credential fields are submitted to.
    credentials:
        Field-name → value map POSTed (or sent as a query on GET) to log in,
        e.g. ``{"username": "admin", "password": "s3cret"}``.
    method:
        ``"POST"`` (default) or ``"GET"``.
    success_text:
        Optional substring that must appear in a successful login response
        body (e.g. ``"Sign out"``). When set, login is only considered
        successful if present.
    failure_text:
        Optional substring that, if present in the login response, marks the
        login as failed (e.g. ``"Invalid credentials"``). Checked before
        ``success_text``.
    logged_out_text:
        Optional substring whose appearance in *any later* response means the
        session was lost (e.g. ``"Please log in"``). Drives mid-scan recovery.
    success_status:
        Optional exact HTTP status that marks a successful login (e.g. ``200``
        or ``302``). When ``None``, any non-5xx/<400 status is accepted.
    harvest_hidden_fields:
        When true (the default), GET each step's own page first and merge any
        hidden-input fields from its login-shaped form underneath the
        explicitly configured fields before submitting — the common way a
        per-session CSRF token gets into a login POST. Silent no-op if the
        page can't be fetched or has no such form, so this is safe to leave on
        even against an app that doesn't use one.
    mfa_url:
        If set, a second step submitted after a successful primary login —
        the MFA/OTP page.
    mfa_data:
        Field-name → value map for the MFA step. A value shaped exactly like
        ``"{totp:BASE32SECRET}"`` is replaced with a live RFC 6238 code at
        submission time (recomputed on every re-authentication); any other
        value is submitted verbatim.
    mfa_method:
        ``"POST"`` (default) or ``"GET"``, same semantics as ``method``.
    mfa_success_text / mfa_failure_text:
        Same semantics as ``success_text``/``failure_text``, for the MFA step.
    """

    def __init__(
        self,
        login_url: str,
        credentials: Dict[str, str],
        *,
        method: str = "POST",
        success_text: Optional[str] = None,
        failure_text: Optional[str] = None,
        logged_out_text: Optional[str] = None,
        success_status: Optional[int] = None,
        harvest_hidden_fields: bool = True,
        mfa_url: Optional[str] = None,
        mfa_data: Optional[Dict[str, str]] = None,
        mfa_method: str = "POST",
        mfa_success_text: Optional[str] = None,
        mfa_failure_text: Optional[str] = None,
    ) -> None:
        self.login_url = login_url
        self.credentials = credentials
        self.method = method.upper()
        self.success_text = success_text
        self.failure_text = failure_text
        self.logged_out_text = logged_out_text
        self.success_status = success_status
        self.harvest_hidden_fields = harvest_hidden_fields
        self.mfa_url = mfa_url
        self.mfa_data = mfa_data or {}
        self.mfa_method = mfa_method.upper()
        self.mfa_success_text = mfa_success_text
        self.mfa_failure_text = mfa_failure_text
        self._login_path = urlsplit(login_url).path or "/"

    # ── Login ────────────────────────────────────────────────────────────────

    def login(self, requester: "Requester") -> bool:
        """
        Run the full login flow through ``requester``'s shared session: the
        primary form submission, then — if configured — the MFA step.

        Resulting cookies persist on ``requester.session`` so every subsequent
        request is authenticated. Returns ``True`` only if every configured
        step succeeded. Credential/code *values* are never logged.
        """
        if not self._submit_primary(requester):
            return False
        if self.mfa_url:
            return self._submit_mfa(requester, self.mfa_url)
        return True

    def _submit_primary(self, requester: "Requester") -> bool:
        fields = self._merge_harvested(requester, self.login_url, self.credentials)
        logger.info(
            "auth: logging in at %s (fields: %s)",
            self.login_url, ", ".join(sorted(fields)),
        )
        if self.method == "GET":
            resp, err = requester.get(self.login_url, params=fields)
        else:
            resp, err = requester.post(self.login_url, data=fields)

        if err or resp is None:
            logger.error("auth: login request failed: %s", err or "no response")
            return False

        ok = self._evaluate(resp, self.success_text, self.failure_text, self.success_status)
        if ok:
            logger.info(
                "auth: login OK (HTTP %d, %d cookie(s) in session)",
                resp.status_code, len(requester.session.cookies),
            )
        else:
            logger.error("auth: login rejected (HTTP %d)", resp.status_code)
        return ok

    def _submit_mfa(self, requester: "Requester", mfa_url: str) -> bool:
        resolved = {
            name: self._resolve_mfa_value(value) for name, value in self.mfa_data.items()
        }
        fields = self._merge_harvested(requester, mfa_url, resolved)
        logger.info("auth: submitting MFA step at %s (fields: %s)", mfa_url, ", ".join(sorted(fields)))

        if self.mfa_method == "GET":
            resp, err = requester.get(mfa_url, params=fields)
        else:
            resp, err = requester.post(mfa_url, data=fields)

        if err or resp is None:
            logger.error("auth: MFA request failed: %s", err or "no response")
            return False

        ok = self._evaluate(resp, self.mfa_success_text, self.mfa_failure_text, None)
        if ok:
            logger.info("auth: MFA OK (HTTP %d)", resp.status_code)
        else:
            logger.error("auth: MFA rejected (HTTP %d)", resp.status_code)
        return ok

    @staticmethod
    def _resolve_mfa_value(value: str) -> str:
        """Compute a live TOTP code for a ``"{totp:SECRET}"`` field value."""
        match = _TOTP_PLACEHOLDER.match(value)
        return totp(match.group(1)) if match else value

    @staticmethod
    def _evaluate(
        resp: "requests.Response",
        success_text: Optional[str],
        failure_text: Optional[str],
        success_status: Optional[int],
    ) -> bool:
        """Shared accept/reject logic for both the primary and MFA steps."""
        body = resp.text or ""
        if failure_text and failure_text in body:
            return False
        if success_status is not None:
            return resp.status_code == success_status
        if success_text is not None:
            return success_text in body
        # No explicit signal configured: treat any <400 status as success.
        return resp.status_code < 400

    def _merge_harvested(
        self, requester: "Requester", page_url: str, fields: Dict[str, str]
    ) -> Dict[str, str]:
        """``fields``, with any harvested hidden inputs filled in underneath."""
        if not self.harvest_hidden_fields:
            return fields
        harvested = self._harvest_hidden_fields(requester, page_url)
        return {**harvested, **fields}

    def _harvest_hidden_fields(self, requester: "Requester", page_url: str) -> Dict[str, str]:
        """
        GET ``page_url`` and pull every hidden-input field's name/value out of
        its login-shaped form — the mechanism most apps use to carry a
        per-session CSRF token that a submission missing it would reject.

        Best-effort and silent: any failure (unreachable page, no matching
        form, parse error) returns ``{}`` so a page that never needed this
        behaves exactly as it did before this existed.
        """
        try:
            resp, err = requester.get(page_url)
            if err or resp is None or resp.status_code >= 400:
                return {}
            forms = HTMLParser().extract_forms(resp.text, page_url)
        except Exception as exc:  # noqa: BLE001 — harvesting is strictly best-effort
            logger.debug("auth: hidden-field harvest failed for %s: %s", page_url, exc)
            return {}

        page_path = urlsplit(page_url).path or "/"
        target = (
            next((f for f in forms if any(fld.field_type == "password" for fld in f.fields)), None)
            or next((f for f in forms if urlsplit(f.action_url).path == page_path), None)
            or (forms[0] if forms else None)
        )
        if target is None:
            return {}
        return {
            field.name: field.default_value
            for field in target.fields
            if field.field_type == "hidden" and field.name
        }

    # ── Session-loss detection + recovery ─────────────────────────────────────

    def is_session_valid(self, resp: "requests.Response") -> bool:
        """
        Return ``False`` when ``resp`` shows the session was lost.

        Signals: the configured ``logged_out_text`` appearing in the body, or a
        redirect whose target path is the login page. With no signal
        configured, the session is always assumed valid (recovery disabled).
        """
        if self.logged_out_text and self.logged_out_text in (resp.text or ""):
            return False
        # Redirect to the login page is the other classic logout tell.
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if location and urlsplit(location).path == self._login_path:
                return False
        return True

    def reauthenticate(self, requester: "Requester") -> bool:
        """Re-run the login after a detected session loss."""
        logger.warning("auth: session lost — re-authenticating")
        return self.login(requester)


class OAuth2Authenticator:
    """
    Authenticate a scan session against an OAuth2/OIDC-protected target by
    obtaining a bearer access token from the authorization server's token
    endpoint (RFC 6749 §4.3/§4.4/§4.1) and attaching it to every request.

    Supports three grants:

    * ``"password"`` — Resource Owner Password Credentials: a test account's
      own ``username``/``password`` exchanged directly for a token.
    * ``"client_credentials"`` — a service-level ``client_id``/
      ``client_secret`` pair, no end-user account at all.
    * ``"authorization_code"`` (+ PKCE, RFC 7636) — the interactive grant.
      Since a CLI scan has no human to click through the authorization
      server's login page, this drives a real headless Chromium (Playwright)
      through it instead: navigate to the ``authorize_url`` with a generated
      PKCE challenge, fill ``login_credentials`` into the rendered login
      form's inputs (matched by ``name`` attribute) and submit. If the code
      hasn't arrived yet (this IdP's own flow renders an MFA page next), the
      same fill-and-submit mechanism runs again against ``mfa_data`` before
      falling through to a no-op when the code already arrived without one.
      Either way, capture the browser's navigation back to ``redirect_uri``
      — intercepted before it actually fires, so ``redirect_uri`` never
      needs to resolve to a real endpoint and the one-time code is never
      consumed by anything but this authenticator — and exchange the code
      plus the PKCE verifier for a token at ``token_url``.

    All three support token refresh via a returned ``refresh_token``.

    Parameters
    ----------
    token_url:
        The authorization server's token endpoint (OIDC providers publish
        this as ``token_endpoint`` in their ``.well-known/openid-configuration``
        document; pass the resolved URL directly — no discovery is done here).
    grant_type:
        ``"password"``, ``"client_credentials"`` or ``"authorization_code"``.
    client_id:
        OAuth2 client identifier.
    client_secret:
        OAuth2 client secret, if the client is confidential (omit for a
        public client).
    username / password:
        Required for the ``"password"`` grant; ignored otherwise.
    scope:
        Optional space-separated scope string (e.g. ``"openid profile"``).
    authorize_url:
        The authorization server's authorization endpoint. Required for
        ``"authorization_code"``.
    redirect_uri:
        The registered redirect URI. Required for ``"authorization_code"``;
        never actually reached (see above).
    login_credentials:
        Field-name → value map filled into the rendered login page's inputs
        (by ``name`` attribute) before it's submitted. Required for
        ``"authorization_code"``.
    mfa_data:
        Optional field-name → value map for an MFA step the IdP's own
        post-login redirect may render next, for ``"authorization_code"``
        only. A value shaped exactly like ``"{totp:BASE32SECRET}"`` is
        replaced with a live RFC 6238 code at submission time (recomputed
        on every re-authentication), same semantics as
        :class:`FormLoginAuthenticator`'s ``mfa_data``; any other value is
        submitted verbatim. Ignored (no-op) if the code already arrived
        without one — this IdP didn't need it.
    nav_timeout_ms:
        Per-step navigation/fill/submit timeout for the browser-driven
        ``"authorization_code"`` flow.
    """

    def __init__(
        self,
        token_url: str,
        grant_type: str,
        client_id: str,
        *,
        client_secret: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        scope: Optional[str] = None,
        authorize_url: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        login_credentials: Optional[Dict[str, str]] = None,
        mfa_data: Optional[Dict[str, str]] = None,
        nav_timeout_ms: int = 20_000,
    ) -> None:
        if grant_type not in ("password", "client_credentials", "authorization_code"):
            raise ValueError(
                f"unsupported OAuth2 grant_type {grant_type!r}; use 'password', "
                "'client_credentials' or 'authorization_code'"
            )
        if grant_type == "password" and not (username and password):
            raise ValueError("the 'password' grant requires both username and password")
        if grant_type == "authorization_code" and not (
            authorize_url and redirect_uri and login_credentials
        ):
            raise ValueError(
                "the 'authorization_code' grant requires authorize_url, "
                "redirect_uri and login_credentials"
            )
        self.token_url = token_url
        self.grant_type = grant_type
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.scope = scope
        self.authorize_url = authorize_url
        self.redirect_uri = redirect_uri
        self.login_credentials = login_credentials or {}
        self.mfa_data = mfa_data or {}
        self.nav_timeout_ms = nav_timeout_ms
        self._expires_at: Optional[float] = None
        self._refresh_token: Optional[str] = None

    def login(self, requester: "Requester") -> bool:
        """Obtain an initial access token and attach it to ``requester``'s session."""
        if self.grant_type == "authorization_code":
            return self._browser_authorize(requester)
        return self._request_token(requester, refresh=False)

    def is_session_valid(self, resp: "requests.Response") -> bool:
        """
        Return ``False`` once the locally tracked token lifetime has elapsed,
        or the resource server rejects the token outright (HTTP 401).
        """
        if resp.status_code == 401:
            return False
        if self._expires_at is not None and time.time() >= self._expires_at:
            return False
        return True

    def reauthenticate(self, requester: "Requester") -> bool:
        """Refresh the access token (or re-run the original grant) after expiry/rejection."""
        logger.warning("auth: OAuth2 token expired/rejected — refreshing")
        if self._refresh_token and self._request_token(requester, refresh=True):
            return True
        # No refresh token (or the refresh was itself rejected): redo the
        # original grant from scratch — for authorization_code this means a
        # fresh browser-driven login, which plain _request_token can't do.
        return self.login(requester)

    def _request_token(self, requester: "Requester", *, refresh: bool) -> bool:
        data: Dict[str, str] = {"client_id": self.client_id}
        if self.client_secret:
            data["client_secret"] = self.client_secret
        if refresh and self._refresh_token:
            data["grant_type"] = "refresh_token"
            data["refresh_token"] = self._refresh_token
        elif self.grant_type == "password":
            data["grant_type"] = "password"
            data["username"] = self.username or ""
            data["password"] = self.password or ""
        else:
            data["grant_type"] = "client_credentials"
        if self.scope:
            data["scope"] = self.scope
        return self._submit_token_request(requester, data, refreshed=refresh)

    def _submit_token_request(
        self, requester: "Requester", data: Dict[str, str], *, refreshed: bool
    ) -> bool:
        resp, err = requester.post(self.token_url, data=data)
        if err or resp is None or resp.status_code >= 400:
            logger.error(
                "auth: OAuth2 token request failed: %s",
                err or f"HTTP {resp.status_code if resp else '?'}",
            )
            return False
        try:
            payload = resp.json()
        except ValueError:
            logger.error("auth: OAuth2 token endpoint did not return JSON")
            return False

        token = payload.get("access_token")
        if not token:
            logger.error("auth: OAuth2 token response missing 'access_token'")
            return False

        requester.session.headers["Authorization"] = f"Bearer {token}"
        expires_in = payload.get("expires_in")
        self._expires_at = time.time() + float(expires_in) if expires_in is not None else None
        self._refresh_token = payload.get("refresh_token", self._refresh_token)
        logger.info(
            "auth: OAuth2 token acquired (%s grant%s)",
            data.get("grant_type"), ", refreshed" if refreshed else "",
        )
        return True

    # ── authorization_code + PKCE (interactive, browser-driven) ────────────

    def _browser_authorize(self, requester: "Requester") -> bool:
        """
        Drive a headless Chromium through the authorization server's login
        page to obtain an authorization code, then exchange it for a token.

        The code is pulled out of the URL of the browser's own outgoing
        navigation request to ``redirect_uri`` (a ``page.on("request")``
        listener, checked against every request as it's dispatched) rather
        than by letting the browser actually load that page and inspecting
        ``page.url`` — Chromium/Playwright don't re-run a page-level
        ``route()`` handler for a redirect hop chained off a request that was
        itself allowed through, so blocking the navigation that way isn't
        reliable. A request event fires for *any* navigation to that URL,
        whichever delivery shape the IdP uses to get there — an HTTP 3xx
        ``Location`` redirect, a client-side JS redirect
        (``window.location``), or a ``<meta http-equiv="refresh">`` — since
        all three end the same way: the browser issuing a request for
        ``redirect_uri?code=...``. Reading the URL off the request means
        ``redirect_uri`` never needs to resolve to anything real, and the
        navigation failing to load (it won't resolve) is harmless — the code
        is already captured by the time the request is dispatched.

        Never raises: a missing Playwright install, a browser that fails to
        launch, a login the IdP rejects, or a navigation that never reaches
        ``redirect_uri`` all degrade to a logged error and ``False`` — the
        same "must not crash the scan" contract as ``DomWatcher.crawl``.
        """
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright
        except ImportError:
            logger.error(
                "auth: the 'authorization_code' grant needs Playwright "
                "(pip install playwright && playwright install chromium)"
            )
            return False

        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(16)
        query = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if self.scope:
            query["scope"] = self.scope
        authorize_url = f"{self.authorize_url}?{urlencode(query)}"

        callback: Dict[str, str] = {}

        def _on_request(request: Any) -> None:
            if "code" in callback:
                return
            try:
                url = request.url
                if not url.startswith(self.redirect_uri or "\0"):
                    return
                qs = parse_qs(urlsplit(url).query)
                if qs.get("code"):
                    callback["code"] = qs["code"][0]
                callback["state"] = (qs.get("state") or [""])[0]
            except Exception:  # noqa: BLE001 — a malformed request must not crash the flow
                return

        try:
            with sync_playwright() as pw:
                try:
                    browser = pw.chromium.launch(headless=True)
                except PlaywrightError as exc:
                    logger.error("auth: could not launch headless Chromium (%s)", exc)
                    return False
                try:
                    page = browser.new_context().new_page()
                    page.set_default_navigation_timeout(self.nav_timeout_ms)
                    page.on("request", _on_request)
                    try:
                        page.goto(authorize_url, wait_until="load")
                    except Exception as exc:  # noqa: BLE001 — see docstring: a nav error
                        # chasing a since-captured (or unreachable) redirect isn't fatal
                        logger.debug("auth: initial navigation ended with %s", exc)
                    if "code" not in callback:
                        self._fill_and_submit(page, self.login_credentials)
                        self._submit_mfa_step(page, callback)
                        deadline = time.time() + self.nav_timeout_ms / 1000
                        while "code" not in callback and time.time() < deadline:
                            page.wait_for_timeout(200)
                finally:
                    browser.close()
        except Exception as exc:  # noqa: BLE001 — a crashed browser must not sink the scan
            logger.error("auth: authorization_code browser flow failed: %s", exc)
            return False

        code = callback.get("code")
        if not code:
            logger.error(
                "auth: authorization_code flow did not yield a code — the login may "
                "have been rejected, or redirect_uri doesn't match what the "
                "authorization server has registered for this client"
            )
            return False
        if callback.get("state") != state:
            logger.error("auth: authorization_code flow state mismatch — aborting")
            return False

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri or "",
            "client_id": self.client_id,
            "code_verifier": verifier,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret
        return self._submit_token_request(requester, data, refreshed=False)

    def _fill_and_submit(self, page: Any, credentials: Dict[str, str]) -> None:
        """
        Fill the currently rendered page's inputs (matched by ``name``) from
        ``credentials`` and submit. Best-effort per field: a selector that
        doesn't match is logged and skipped rather than aborting the whole
        flow, since the subsequent wait for ``redirect_uri`` is what
        ultimately decides success. ``page.fill`` already waits (up to
        ``nav_timeout_ms``) for its selector to appear, so this tolerates
        being called right after a prior submit kicked off a navigation —
        used for both the primary login form and an optional MFA step.
        """
        for name, value in credentials.items():
            try:
                page.fill(f'input[name="{name}"]', value, timeout=self.nav_timeout_ms)
            except Exception as exc:  # noqa: BLE001 — best effort, see docstring
                logger.debug("auth: could not fill form field %r: %s", name, exc)
        try:
            page.click('button[type="submit"], input[type="submit"]', timeout=self.nav_timeout_ms)
        except Exception:  # noqa: BLE001 — no submit button found, fall back to Enter
            try:
                page.keyboard.press("Enter")
            except Exception as exc:  # noqa: BLE001
                logger.debug("auth: could not submit form: %s", exc)

    def _submit_mfa_step(self, page: Any, callback: Dict[str, str]) -> None:
        """
        If an MFA step is configured and the authorization code hasn't
        already arrived (e.g. this IdP accepted the primary login outright),
        fill and submit it on whatever page the IdP's own post-login
        redirect rendered next — same fill-by-name/submit mechanism as the
        primary step, with any ``{totp:SECRET}`` field resolved to a live
        code at submission time. Best-effort and silent: if the code
        already arrived, or no MFA page ever appears within the usual nav
        timeout, this is a no-op — the primary step and the polling loop
        that follows are what ultimately decide success or failure.
        """
        if not self.mfa_data or "code" in callback:
            return
        resolved = {
            name: FormLoginAuthenticator._resolve_mfa_value(value)
            for name, value in self.mfa_data.items()
        }
        self._fill_and_submit(page, resolved)


def _pkce_pair() -> Tuple[str, str]:
    """Generate an RFC 7636 PKCE ``(code_verifier, code_challenge)`` pair (S256)."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def parse_login_data(raw: str) -> Dict[str, str]:
    """
    Parse a ``--login-data`` string into a credential dict.

    Accepts ``"field=value&field2=value2"`` (URL-form style). A value may
    itself contain ``=``; only the first ``=`` in each pair splits the field
    from the value.
    """
    creds: Dict[str, str] = {}
    for pair in raw.split("&"):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise ValueError(f"login field missing '=': {pair!r}")
        name, value = pair.split("=", 1)
        name = name.strip()
        if not name:
            raise ValueError(f"login field has empty name: {pair!r}")
        creds[name] = value
    if not creds:
        raise ValueError("no login fields parsed")
    return creds
