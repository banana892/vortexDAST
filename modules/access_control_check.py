"""
VortexDAST – modules/access_control_check.py
────────────────────────────────────────────────────────────────────────────
Broken Access Control detection module (OWASP A01:2021).

Because the scanner's module interface is per-endpoint with a single shared
:class:`~core.requester.Requester`, this module implements access-control
testing *without* a full dual-mode crawler refactor:

1.  **Unauthenticated access to a protected resource** (``firm``):
    When the scan is running with credentials (session cookies, an
    ``Authorization`` header, or HTTP auth), each endpoint whose path looks
    sensitive (``/admin``, ``/account``, ``/dashboard``, …) is re-requested
    through a credential-stripped clone of the requester. If the anonymous
    request returns HTTP 200 with a body essentially identical to the
    authenticated one — and does not look like a login / access-denied page —
    the resource is served to anyone, i.e. broken access control.

2.  **Insecure Direct Object Reference / horizontal access** (``tentative``):
    For parameters that carry a numeric object reference (``id``, ``user_id``,
    ``order``, …), the reference is incremented/decremented and re-requested.
    A 200 response of comparable size but *different* content suggests another
    user's object is reachable. Reported as ``tentative`` (manual confirmation
    required) because a DAST cannot know resource ownership. Runs **only when a
    session is configured** — without an authorization boundary to cross, a
    differing public record is expected content, not IDOR.

3.  **Role matrix** (``firm``, only when a second identity is configured via
    ``--role2-login-data``): the same sensitive-path check as Part 1, run
    against a second, independently authenticated session instead of an
    anonymous one — surfaces vertical privilege escalation (a lower-privilege
    second account reaching an admin-shaped page). Additionally, every
    object-reference parameter the primary session observed is re-requested
    *unmodified* through the second session — if a genuinely distinct account
    gets the exact same object back, that's direct (not guessed) evidence of
    horizontal access control failure, so it is reported at ``firm``
    confidence rather than Part 2's ``tentative`` ID-swap guess.

False-Positive Reduction
------------------------
*   Part 1 runs only when auth is configured and only on sensitive paths, so
    genuinely public pages are not flagged.
*   A login / access-denied body (or a redirect to one) is treated as correctly
    protected.
*   Part 2 (IDOR) runs only when auth is configured, and only swaps params
    whose name looks like an object reference (curated list or id-like suffix),
    so numeric navigation params (``page``, ``offset``, ``year``, …) are not
    probed.
*   IDOR findings are ``tentative`` and gated on comparable-size, differing-but
    -valid-looking responses.

Safety
------
*   Only GET requests are issued; no state-changing verbs, no destructive input.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple
from urllib.parse import urlencode, urlparse

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc
from core.requester import Requester

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_ACCESS_CONTROL_PATH = os.path.join(_PAYLOADS_DIR, "access_control.json")

# Authenticated and anonymous bodies within this length ratio are "the same page".
_SAME_BODY_RATIO = 0.10  # 10 %
# IDOR: a swapped-ID response must differ from baseline by at least this much…
_IDOR_MIN_DIFF = 0.10
# …while staying within this size band of the baseline (so it still looks like a record).
_IDOR_MIN_SIZE_BAND = 0.5
_IDOR_MAX_SIZE_BAND = 2.0
# Numeric params with an id-like name are treated as object references even when
# the exact name is not in the curated list (covers custom *_id / *Id / *_ref).
_ID_NAME_SUFFIXES = ("id", "_id", "uid", "uuid", "ref", "_ref", "key")

# Unauthenticated access to a protected resource: network, low complexity, no
# privileges/UI; confidentiality High (sensitive page exposed), integrity Low.
# AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:L / A:N  → 8.2 (HIGH)
_CVSS_VECTOR_UNAUTH = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="N"
)
_CVSS_SCORE_UNAUTH: float = cvss_calc(_CVSS_VECTOR_UNAUTH)

# IDOR (heuristic horizontal access): higher complexity to confirm blindly;
# confidentiality High if real, no integrity/availability from a GET probe.
# AV:N / AC:H / PR:N / UI:N / S:U / C:H / I:N / A:N  → 5.9 (MEDIUM)
_CVSS_VECTOR_IDOR = build_vector(
    AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="N", A="N"
)
_CVSS_SCORE_IDOR: float = cvss_calc(_CVSS_VECTOR_IDOR)

# Role-matrix cross-identity object access: no guessing involved (a second,
# genuinely distinct account retrieved the exact reference), only needs an
# account of its own to exploit.
# AV:N / AC:L / PR:L / UI:N / S:U / C:H / I:N / A:N
_CVSS_VECTOR_ROLE_IDOR = build_vector(
    AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="N", A="N"
)
_CVSS_SCORE_ROLE_IDOR: float = cvss_calc(_CVSS_VECTOR_ROLE_IDOR)


class AccessControlCheckModule(BaseScannerModule):
    """Broken Access Control detection (unauthenticated exposure + IDOR)."""

    name: str = "access_control_check"
    description: str = (
        "Detects broken access control: re-requests sensitive endpoints with "
        "credentials stripped to find unauthenticated exposure, and swaps "
        "numeric object references to surface potential IDOR."
    )

    def __init__(self, requester: Any, payloads_path: Optional[str] = None) -> None:
        super().__init__(requester)
        path = payloads_path or _ACCESS_CONTROL_PATH
        (
            self._sensitive_patterns,
            self._login_indicators,
            self._idor_param_names,
        ) = _load_access_control_rules(path)

        self._auth_configured = _detect_auth(requester)
        self._unauth_requester: Optional[Requester] = None
        self._role_requester: Optional[Requester] = None

        # Thread-safe dedup: assess each origin+path only once.
        self._seen_lock = threading.Lock()
        self._seen_unauth: Set[str] = set()
        self._seen_idor: Set[str] = set()
        self._seen_role: Set[str] = set()
        self._seen_role_idor: Set[str] = set()

    def set_role_requester(self, requester: Requester) -> None:
        """
        Configure a second, independently authenticated session (role-matrix
        testing). When set, every endpoint is additionally checked against
        this identity: sensitive-path reach (vertical escalation) and direct
        cross-identity object access (horizontal escalation). See class
        docstring Part 3.
        """
        self._role_requester = requester

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        findings: List[Finding] = []

        if self._auth_configured:
            findings.extend(self._check_unauth_access(endpoint.url))

        # IDOR is a *horizontal access-control* flaw: it only has meaning when
        # there is a session whose authorization boundary a swapped reference
        # could cross. Without authentication every response is public, so a
        # differing record for a different id is expected content, not a
        # vulnerability — running the swap there only produces false positives
        # on public catalogues and pagination. Gate it on auth, like Part 1.
        if self._auth_configured:
            if endpoint.query_params:
                findings.extend(self._check_idor(endpoint.url, endpoint.query_params))
            for link in endpoint.links:
                link_params = getattr(link, "query_params", None)
                if link_params:
                    findings.extend(self._check_idor(link.url, link_params))

        if self._role_requester is not None:
            findings.extend(self._check_role_access(endpoint.url))
            if endpoint.query_params:
                findings.extend(self._check_role_idor(endpoint.url, endpoint.query_params))
            for link in endpoint.links:
                link_params = getattr(link, "query_params", None)
                if link_params:
                    findings.extend(self._check_role_idor(link.url, link_params))

        return findings

    # ── Part 1: unauthenticated access to protected resource ───────────────────

    def _check_unauth_access(self, url: str) -> List[Finding]:
        other = self._get_unauth_requester()
        if other is None:
            return []
        return self._check_cross_identity_access(
            url,
            other=other,
            dedup_set=self._seen_unauth,
            other_label="Anonymous (no cookies/auth)",
            title="Broken Access Control — Unauthenticated Access to Protected Resource",
            description=(
                "The sensitive endpoint '{url}' returned effectively the same "
                "content when requested without any session cookies or "
                "authentication headers as it did when authenticated. The "
                "resource is therefore accessible to anonymous users, which "
                "indicates missing or broken server-side authorization checks."
            ),
            log_label="unauthenticated access to sensitive resource",
        )

    def _check_role_access(self, url: str) -> List[Finding]:
        """Part 3 (vertical): can the second role-matrix identity reach this too?"""
        assert self._role_requester is not None
        return self._check_cross_identity_access(
            url,
            other=self._role_requester,
            dedup_set=self._seen_role,
            other_label="Second role-matrix identity",
            title="Broken Access Control — Second Identity Reaches Sensitive Resource",
            description=(
                "The sensitive endpoint '{url}' returned effectively the same "
                "content for the second, independently authenticated identity "
                "(--role2-login-data) as it did for the primary scan session. "
                "If that second identity is meant to hold lower privileges, this "
                "is vertical privilege escalation — missing or broken "
                "role-based authorization."
            ),
            log_label="role-matrix: second identity reaches sensitive resource",
        )

    def _check_cross_identity_access(
        self,
        url: str,
        *,
        other: Requester,
        dedup_set: Set[str],
        other_label: str,
        title: str,
        description: str,
        log_label: str,
    ) -> List[Finding]:
        """
        Shared logic behind Part 1 (anonymous) and Part 3 (role matrix):
        fetch ``url`` with the primary session and with ``other``; flag it
        when both return essentially the same HTTP 200 content and ``other``'s
        response isn't itself a login/access-denied page.
        """
        if not self._is_sensitive_path(url):
            return []

        key = _origin_path_key(url)
        with self._seen_lock:
            if key in dedup_set:
                return []
            dedup_set.add(key)

        primary_resp, primary_err = self.requester.get(url)
        if primary_err or primary_resp is None or primary_resp.status_code != 200:
            return []

        other_resp, other_err = other.get(url)
        if other_err or other_resp is None:
            return []

        # Correctly protected: explicit deny / auth-required status.
        if other_resp.status_code in (401, 403):
            return []
        if other_resp.status_code != 200:
            return []
        # Redirected somewhere else (e.g. a login page) → treated as protected.
        if other_resp.history and _path_of(other_resp.url) != _path_of(url):
            return []
        # Body looks like a login / access-denied page → protected.
        if self._looks_like_login(other_resp.text):
            return []

        # Both 200 and bodies essentially identical → served to this identity too.
        if not _bodies_similar(primary_resp.text, other_resp.text):
            return []

        logger.info("⚡ BAC: %s — %s", log_label, url)
        return [
            Finding(
                title=title,
                severity=Severity.HIGH,
                confidence=Confidence.FIRM,
                url=url,
                parameter=None,
                payload=None,
                evidence=(
                    f"Primary-session response: HTTP {primary_resp.status_code}, "
                    f"{len(primary_resp.text)} bytes. {other_label} response: HTTP "
                    f"{other_resp.status_code}, {len(other_resp.text)} bytes — "
                    "essentially identical content."
                ),
                description=description.format(url=url),
                remediation=(
                    "Enforce authorization on the server for every sensitive route — "
                    "never rely on the UI hiding links. Verify the session/identity "
                    "and the user's permission to the specific resource before "
                    "returning it, and return 401/403 (or redirect to login) for "
                    "requests that should not see it."
                ),
                cvss_vector=_CVSS_VECTOR_UNAUTH,
                cvss_score=_CVSS_SCORE_UNAUTH,
                extra={
                    "primary_status": primary_resp.status_code,
                    "other_status": other_resp.status_code,
                    "primary_len": len(primary_resp.text),
                    "other_len": len(other_resp.text),
                    "other_identity": other_label,
                    "module": self.name,
                },
            )
        ]

    # ── Part 2: IDOR / object-reference swapping ───────────────────────────────

    def _check_idor(
        self, url: str, params: Dict[str, List[str]]
    ) -> List[Finding]:
        findings: List[Finding] = []
        base_params = {k: v[0] for k, v in params.items() if v}

        for param, value in base_params.items():
            if not self._is_object_ref(param, value):
                continue

            key = f"{_origin_path_key(url)}::{param}"
            with self._seen_lock:
                if key in self._seen_idor:
                    continue
                self._seen_idor.add(key)

            baseline = self._get_body_if_200(url, base_params)
            if baseline is None:
                continue

            for delta in (1, -1):
                try:
                    swapped = int(value) + delta
                except ValueError:
                    break
                if swapped < 0:
                    continue
                modified = dict(base_params)
                modified[param] = str(swapped)
                candidate = self._get_body_if_200(url, modified)
                if candidate is None:
                    continue

                if self._is_idor_hit(baseline, candidate):
                    findings.append(
                        self._idor_finding(url, param, value, str(swapped), baseline, candidate)
                    )
                    break  # One hit per parameter is enough.

        return findings

    def _is_idor_hit(self, baseline: str, candidate: str) -> bool:
        len_b, len_c = len(baseline), len(candidate)
        if len_b == 0 or len_c == 0:
            return False
        # Comparable size (still looks like a valid record, not an error page).
        ratio = len_c / len_b
        if not (_IDOR_MIN_SIZE_BAND <= ratio <= _IDOR_MAX_SIZE_BAND):
            return False
        # But the content must actually differ (another object returned).
        diff = abs(len_b - len_c) / max(len_b, len_c)
        if diff >= _IDOR_MIN_DIFF:
            return True
        # Comparable (or equal) length but different body: another record.
        return baseline != candidate

    def _idor_finding(
        self,
        url: str,
        param: str,
        original: str,
        swapped: str,
        baseline: str,
        candidate: str,
    ) -> Finding:
        logger.info(
            "⚡ BAC/IDOR: %s | param=%s | %s→%s", url, param, original, swapped
        )
        return Finding(
            title="Potential IDOR — Object Reference Swap Returned Different Record",
            severity=Severity.MEDIUM,
            confidence=Confidence.TENTATIVE,
            url=url,
            parameter=param,
            payload=f"{param}={swapped} (was {original})",
            evidence=(
                f"Baseline ({param}={original}): {len(baseline)} bytes. "
                f"Swapped ({param}={swapped}): {len(candidate)} bytes — HTTP 200 "
                "with different, comparable-size content."
            ),
            description=(
                f"Changing the numeric object reference '{param}' from {original} to "
                f"{swapped} returned a different HTTP 200 record of comparable size. "
                "If these records belong to different users/tenants, the endpoint is "
                "missing per-object authorization (Insecure Direct Object Reference). "
                "Manual confirmation of resource ownership is required."
            ),
            remediation=(
                "Enforce object-level authorization: verify the authenticated user "
                "owns or may access the requested object before returning it. Prefer "
                "unguessable identifiers (UUIDs) and scope queries to the current "
                "user/tenant."
            ),
            cvss_vector=_CVSS_VECTOR_IDOR,
            cvss_score=_CVSS_SCORE_IDOR,
            extra={
                "original_value": original,
                "swapped_value": swapped,
                "baseline_len": len(baseline),
                "candidate_len": len(candidate),
                "module": self.name,
            },
        )

    # ── Part 3b: role matrix — direct cross-identity object access ─────────────

    def _check_role_idor(
        self, url: str, params: Dict[str, List[str]]
    ) -> List[Finding]:
        """
        Re-request every object-reference parameter's *unmodified* value
        through the second role-matrix identity. Unlike Part 2, there is no
        guessing: a genuinely distinct, independently authenticated account
        either gets the same record back or it doesn't, so a hit is reported
        at ``firm`` confidence.
        """
        assert self._role_requester is not None
        findings: List[Finding] = []
        base_params = {k: v[0] for k, v in params.items() if v}

        for param, value in base_params.items():
            if not self._is_object_ref(param, value):
                continue

            key = f"{_origin_path_key(url)}::{param}"
            with self._seen_lock:
                if key in self._seen_role_idor:
                    continue
                self._seen_role_idor.add(key)

            baseline = self._get_body_if_200(url, base_params)
            if baseline is None:
                continue
            candidate = self._get_body_if_200(url, base_params, requester=self._role_requester)
            if candidate is None or not candidate or self._looks_like_login(candidate):
                continue

            findings.append(self._role_idor_finding(url, param, value, baseline, candidate))

        return findings

    def _role_idor_finding(
        self, url: str, param: str, value: str, baseline: str, candidate: str
    ) -> Finding:
        logger.info(
            "⚡ BAC/role-matrix: second identity retrieved %s's own object %s=%s",
            url, param, value,
        )
        return Finding(
            title="Broken Access Control — Second Identity Accessed Same Object Reference",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            parameter=param,
            payload=f"{param}={value}",
            evidence=(
                f"Primary session ({param}={value}): {len(baseline)} bytes, HTTP 200. "
                f"Second role-matrix identity requested the identical reference and "
                f"also got HTTP 200, {len(candidate)} bytes — not a login/denied page."
            ),
            description=(
                f"The object reference '{param}={value}' at '{url}', reachable by the "
                "primary scan session, was also retrievable by a second, "
                "independently authenticated identity (--role2-login-data) without "
                "modification. If that object belongs to the primary identity only, "
                "this is a confirmed horizontal access-control failure — no guessing "
                "was needed, a genuinely distinct account retrieved it directly."
            ),
            remediation=(
                "Enforce object-level authorization: verify the authenticated user "
                "owns or may access the requested object before returning it. Prefer "
                "unguessable identifiers (UUIDs) and scope queries to the current "
                "user/tenant."
            ),
            cvss_vector=_CVSS_VECTOR_ROLE_IDOR,
            cvss_score=_CVSS_SCORE_ROLE_IDOR,
            extra={
                "object_value": value,
                "baseline_len": len(baseline),
                "candidate_len": len(candidate),
                "module": self.name,
            },
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _get_body_if_200(
        self, url: str, params: Dict[str, str], *, requester: Optional[Requester] = None
    ) -> Optional[str]:
        parsed = urlparse(url)
        full_url = parsed._replace(query=urlencode(params)).geturl()
        resp, err = (requester or self.requester).get(full_url)
        if err or resp is None or resp.status_code != 200:
            return None
        return resp.text

    def _is_sensitive_path(self, url: str) -> bool:
        path = _path_of(url)
        return any(p.search(path) for p in self._sensitive_patterns)

    def _is_object_ref(self, param: str, value: str) -> bool:
        if not value.isdigit():
            return False
        name = param.lower()
        if name in self._idor_param_names:
            return True
        # Fall back to id-like naming only. A bare numeric value is not enough:
        # navigational/dimension params (page, offset, limit, year, width, …)
        # are numeric too, and swapping them is not an object-reference test.
        return name.endswith(_ID_NAME_SUFFIXES)

    def _looks_like_login(self, body: str) -> bool:
        body_lower = body.lower()
        return any(ind in body_lower for ind in self._login_indicators)

    def _get_unauth_requester(self) -> Optional[Requester]:
        if self._unauth_requester is not None:
            return self._unauth_requester
        with self._seen_lock:
            if self._unauth_requester is not None:
                return self._unauth_requester
            self._unauth_requester = _clone_without_auth(self.requester)
        return self._unauth_requester


# ─────────────────────────────────────────────────────────────────────────────
# Module-level helpers
# ─────────────────────────────────────────────────────────────────────────────


def _path_of(url: str) -> str:
    return urlparse(url).path or "/"


def _origin_path_key(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"


def _bodies_similar(a: str, b: str) -> bool:
    len_a, len_b = len(a), len(b)
    if len_a == 0 and len_b == 0:
        return True
    if len_a == 0 or len_b == 0:
        return False
    ratio = abs(len_a - len_b) / max(len_a, len_b)
    return ratio <= _SAME_BODY_RATIO


def _detect_auth(requester: Any) -> bool:
    """Return True if the shared requester carries any authentication state."""
    session = getattr(requester, "session", None)
    if session is None:
        return False
    try:
        if len(session.cookies) > 0:
            return True
    except TypeError:
        pass
    if getattr(session, "auth", None):
        return True
    headers = getattr(session, "headers", {}) or {}
    return any(k.lower() == "authorization" for k in headers)


def _clone_without_auth(requester: Any) -> Optional[Requester]:
    """Build a Requester mirroring non-auth settings but carrying no credentials."""
    try:
        session = requester.session
        proxies = getattr(session, "proxies", {}) or {}
        proxy = proxies.get("https") or proxies.get("http")
        user_agent = session.headers.get("User-Agent", "VortexDAST/1.0")
        return Requester(
            timeout=getattr(requester, "timeout", 10),
            user_agent=user_agent,
            rate_limit_rps=getattr(requester, "rate_limit_rps", 5.0),
            verify_ssl=getattr(requester, "verify_ssl", True),
            proxy=proxy,
            max_workers=getattr(requester, "max_workers", 10),
        )
    except Exception as exc:  # noqa: BLE001 — degrade gracefully, never crash a scan
        logger.warning("access_control_check: could not build unauth requester: %s", exc)
        return None


def _load_access_control_rules(
    path: str,
) -> Tuple[List[Pattern[str]], List[str], Set[str]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.error("access_control.json not found at %s", path)
        return [], [], set()
    except json.JSONDecodeError as exc:
        logger.error("access_control.json parse error: %s", exc)
        return [], [], set()

    patterns: List[Pattern[str]] = []
    for raw in data.get("sensitive_path_patterns", []):
        try:
            patterns.append(re.compile(raw, re.IGNORECASE))
        except re.error as exc:
            logger.warning("Invalid sensitive-path regex '%s': %s", raw, exc)

    login_indicators = [s.lower() for s in data.get("login_indicators", [])]
    idor_names = {s.lower() for s in data.get("idor_param_names", [])}

    logger.debug(
        "access_control_check: loaded %d path patterns, %d login indicators, "
        "%d idor names from %s",
        len(patterns), len(login_indicators), len(idor_names), path,
    )
    return patterns, login_indicators, idor_names
