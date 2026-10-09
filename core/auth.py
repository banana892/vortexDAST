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

Scope of this scaffold
-----------------------
Form-based login (GET or POST of credential fields) is implemented and tested.
OAuth2/OIDC redirect flows, CSRF-token harvesting from the login page, and
multi-step / MFA logins are intentionally left as follow-ups — the class is
structured so they slot in as additional ``login`` strategies without touching
the recovery plumbing.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Dict, Optional
from urllib.parse import urlsplit

if TYPE_CHECKING:  # avoid a runtime import cycle
    import requests

    from core.requester import Requester

logger = logging.getLogger("vortexdast")


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
    ) -> None:
        self.login_url = login_url
        self.credentials = credentials
        self.method = method.upper()
        self.success_text = success_text
        self.failure_text = failure_text
        self.logged_out_text = logged_out_text
        self.success_status = success_status
        self._login_path = urlsplit(login_url).path or "/"

    # ── Login ────────────────────────────────────────────────────────────────

    def login(self, requester: "Requester") -> bool:
        """
        Submit the login form through ``requester``'s shared session.

        Resulting cookies persist on ``requester.session`` so every subsequent
        request is authenticated. Returns ``True`` on success. Credential
        *values* are never logged.
        """
        logger.info(
            "auth: logging in at %s (fields: %s)",
            self.login_url, ", ".join(sorted(self.credentials)),
        )
        if self.method == "GET":
            resp, err = requester.get(self.login_url, params=self.credentials)
        else:
            resp, err = requester.post(self.login_url, data=self.credentials)

        if err or resp is None:
            logger.error("auth: login request failed: %s", err or "no response")
            return False

        ok = self._login_succeeded(resp)
        if ok:
            logger.info(
                "auth: login OK (HTTP %d, %d cookie(s) in session)",
                resp.status_code, len(requester.session.cookies),
            )
        else:
            logger.error("auth: login rejected (HTTP %d)", resp.status_code)
        return ok

    def _login_succeeded(self, resp: "requests.Response") -> bool:
        body = resp.text or ""
        if self.failure_text and self.failure_text in body:
            return False
        if self.success_status is not None:
            return resp.status_code == self.success_status
        if self.success_text is not None:
            return self.success_text in body
        # No explicit signal configured: treat any <400 status as success.
        return resp.status_code < 400

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
