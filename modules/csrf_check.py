"""
VortexDAST – modules/csrf_check.py
────────────────────────────────────────────────────────────────────────────
Cross-Site Request Forgery (CSRF) Form Auditing Module.

Detection Strategy
------------------
This is a **passive** module — it makes zero additional HTTP requests beyond
what the crawler already performed.  It inspects the pre-parsed ``endpoint.forms``
data to identify state-changing HTML forms that lack anti-CSRF token fields.

Algorithm:
  1. Iterate over all forms collected by the crawler for each endpoint.
  2. Filter to **state-changing forms**:
       - Method is POST, PUT, or DELETE (case-insensitive).
       - GET forms whose action URL path ends in a destructive keyword
         (``/delete``, ``/remove``, ``/update``, ``/edit``, ``/destroy``).
  3. For each qualifying form, check whether any ``<input type="hidden">``
     field name matches a known anti-CSRF token name heuristic (see
     :data:`_CSRF_TOKEN_NAMES`).
  4. If **no matching token field is found**, emit a MEDIUM-severity finding.

False-Positive Suppression
--------------------------
*   Token matching is case-insensitive and uses ``in`` substring matching so
    that framework-specific names (e.g. ``__csrf_magic``, ``form_csrf_token``)
    are recognised even if they don't exactly match the list.
*   GET forms are only flagged when their action targets a known-destructive
    path — plain search forms are not reported.
*   If a form has no fields at all (e.g. it only contains a submit button),
    it is skipped — there is nothing to audit.

CVSS v3.1 Vector for CSRF findings
-----------------------------------
  AV:N / AC:L / PR:N / UI:R / S:C / C:N / I:H / A:N  → 7.4  (HIGH)

Severity is HIGH (7.4) rather than MEDIUM because a missing CSRF token on a
state-changing form can lead to full account takeover or irreversible data
modification with no interaction required from the victim beyond clicking a link.
"""

from __future__ import annotations

import logging
import re
from typing import List, Set
from urllib.parse import urlparse

from .base import BaseScannerModule, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc
from core.requester import Requester

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 vector for CSRF findings
# ─────────────────────────────────────────────────────────────────────────────
# AV:N / AC:L / PR:N / UI:R / S:C / C:N / I:H / A:N  → 7.4
_CVSS_VECTOR_CSRF = build_vector(
    AV="N", AC="L", PR="N", UI="R", S="C", C="N", I="H", A="N"
)
_CVSS_SCORE_CSRF: float = cvss_calc(_CVSS_VECTOR_CSRF)  # 7.4

# ─────────────────────────────────────────────────────────────────────────────
# Token name heuristics
# ─────────────────────────────────────────────────────────────────────────────

#: Lowercase substrings that indicate an anti-CSRF token hidden field.
#: Matching is done with ``token_name_lower in _CSRF_TOKEN_NAMES`` OR
#: ``any(hint in token_name_lower for hint in _CSRF_TOKEN_HINTS)``.
_CSRF_TOKEN_NAMES: Set[str] = {
    "csrf_token",
    "csrftoken",
    "_csrf",
    "csrf",
    "xsrf_token",
    "xsrftoken",
    "authenticity_token",
    "__requestverificationtoken",
    "nonce",
    "_token",
    "anti_csrf",
    "anticsrf",
    "form_token",
    "_form_key",
    "security_token",
    "verify_token",
    "requesttoken",
    "form_key",
    "_nonce",
    "token",
}

#: Hint substrings for substring-based matching of non-standard token names
#: (e.g. ``"__csrf_magic"`` → contains ``"csrf"``).
_CSRF_TOKEN_HINTS: Set[str] = {"csrf", "xsrf", "nonce", "antiforgery"}

#: HTTP methods that represent state-changing operations.
_STATE_CHANGING_METHODS: Set[str] = {"POST", "PUT", "DELETE", "PATCH"}

#: Path suffixes that indicate a destructive action even for GET forms.
_DESTRUCTIVE_PATHS: tuple[str, ...] = (
    "/delete", "/remove", "/update", "/edit", "/destroy",
    "/deactivate", "/disable", "/reset",
)


def _is_state_changing_form(action_url: str, method: str) -> bool:
    """
    Return ``True`` if the form is state-changing and should be audited.

    Parameters
    ----------
    action_url : str
        The ``action`` attribute of the form (absolute URL).
    method : str
        The HTTP method of the form (raw from HTML, may be any case).
    """
    norm_method = method.strip().upper()
    if norm_method in _STATE_CHANGING_METHODS:
        return True

    # GET forms targeting destructive paths.
    if norm_method == "GET":
        path = urlparse(action_url).path.lower().rstrip("/")
        return any(path.endswith(d) for d in _DESTRUCTIVE_PATHS)

    return False


def _has_csrf_token(form) -> bool:  # type: ignore[type-arg]
    """
    Return ``True`` if the form contains a field whose name matches a known
    CSRF token heuristic.

    Parameters
    ----------
    form : ParsedForm
        A parsed form object with a ``fields`` list of :class:`~core.parser.FormField`.
    """
    for field in form.fields:
        if not field.name:
            continue
        name_lower = field.name.strip().lower()
        # Exact match against known names.
        if name_lower in _CSRF_TOKEN_NAMES:
            return True
        # Substring match for non-standard naming conventions.
        if any(hint in name_lower for hint in _CSRF_TOKEN_HINTS):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# CSRF Check Module
# ─────────────────────────────────────────────────────────────────────────────


class CSRFCheckModule(BaseScannerModule):
    """
    Passive CSRF form auditing module.

    Inspects all HTML forms already collected by the crawler.  State-changing
    forms (POST, PUT, DELETE, PATCH, and destructive-path GET forms) that lack
    a recognisable anti-CSRF token hidden field are reported as findings.

    This module makes **zero additional HTTP requests**.
    """

    name: str = "csrf_check"
    description: str = (
        "Passively audits HTML forms on state-changing endpoints for missing "
        "CSRF protection tokens. Zero additional HTTP requests."
    )

    def __init__(self, requester: Requester) -> None:
        super().__init__(requester)

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        """
        Audit all forms on ``endpoint`` for missing CSRF tokens.

        Parameters
        ----------
        endpoint : CrawledEndpoint
            A crawled endpoint with its associated parsed forms.

        Returns
        -------
        list[Finding]
            One finding per state-changing form that lacks an anti-CSRF token.
            Empty list when all forms are properly protected or no forms exist.
        """
        findings: List[Finding] = []

        if not endpoint.forms:
            logger.debug("csrf_check: no forms on %s — skipping.", endpoint.url)
            return findings

        for form in endpoint.forms:
            method: str = getattr(form, "method", "GET") or "GET"
            action_url: str = getattr(form, "action_url", endpoint.url) or endpoint.url

            # Skip forms with no input fields — nothing to audit.
            if not form.fields:
                logger.debug(
                    "csrf_check: form with action=%s has no fields — skipping.", action_url
                )
                continue

            if not _is_state_changing_form(action_url, method):
                logger.debug(
                    "csrf_check: form method=%s action=%s is not state-changing — skipping.",
                    method, action_url,
                )
                continue

            if _has_csrf_token(form):
                logger.debug(
                    "csrf_check: form action=%s has CSRF token — OK.", action_url
                )
                continue

            # No CSRF token found on a state-changing form — report it.
            field_names = [f.name for f in form.fields if f.name]
            logger.info(
                "csrf_check: MISSING CSRF token on %s [%s] — fields: %s",
                action_url, method.upper(), field_names,
            )

            findings.append(
                Finding(
                    title="Missing CSRF Token on State-Changing Form",
                    severity=Severity.HIGH,
                    url=endpoint.url,
                    parameter=f"form[action={action_url}][method={method.upper()}]",
                    payload="(passive audit — no payload injected)",
                    evidence=(
                        f"Form submits to {action_url!r} via {method.upper()} "
                        f"with no detectable anti-CSRF hidden field. "
                        f"Discovered fields: {field_names!r}"
                    ),
                    remediation=(
                        "Implement a cryptographically random, unpredictable, "
                        "per-session (or per-form) CSRF token. Include it as a hidden "
                        "field in every state-changing form and validate it server-side "
                        "on every submission. Frameworks such as Django, Rails, and "
                        "Spring Security provide built-in CSRF middleware — enable it. "
                        "Alternatively, use the SameSite=Strict or SameSite=Lax "
                        "cookie attribute as a complementary defence."
                    ),
                    cvss_vector=_CVSS_VECTOR_CSRF,
                    cvss_score=_CVSS_SCORE_CSRF,
                )
            )

        return findings
