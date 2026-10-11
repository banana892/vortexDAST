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

Scope of this scaffold
-----------------------
Form-based login (GET or POST), CSRF-token harvesting, and two-step/MFA logins
are implemented and tested. OAuth2/OIDC token flows and a multi-identity
"role matrix" comparison are intentionally left as follow-ups — the class is
structured so they slot in as additional strategies without touching the
recovery plumbing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import struct
import time
from typing import TYPE_CHECKING, Dict, Optional
from urllib.parse import urlsplit

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
