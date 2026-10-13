"""
VortexDAST – modules/cors_check.py
────────────────────────────────────────────────────────────────────────────
CORS Misconfiguration detection module (OWASP A05:2021 / CWE-942).

Detection Strategy
------------------
Runs once per distinct origin+path (like ``access_control_check``'s Part 1
— no per-parameter fuzzing, this is a response-header check). For each of
two test ``Origin`` header values — a random attacker-controlled origin and
the literal string ``"null"`` (reachable via a sandboxed iframe, a `data:`
URI, or a local-file context) — issues a GET with that ``Origin`` and
inspects the response:

*   ``Access-Control-Allow-Origin`` (ACAO) reflects the *exact* ``Origin``
    we sent (not a fixed, known-safe value), **and**
    ``Access-Control-Allow-Credentials: true`` is also set
    → **HIGH**/``CERTAIN``: any origin can make a credentialed
    cross-origin request and read the response with the victim's cookies —
    the textbook critical CORS misconfiguration.
*   ACAO is the literal wildcard ``"*"`` **and** credentials are also
    allowed → **HIGH**/``CERTAIN`` too. Modern browsers refuse to honour
    this combination (the Fetch spec forbids it), but a server sending it
    is unambiguously broken CORS logic and worth flagging regardless of
    what today's browsers do with it.
*   ACAO reflects the origin (or is ``"*"``) **without** credentials
    → **MEDIUM**/``TENTATIVE``: any site can read the response, but not
    with the victim's session — often intentional for a public API, so
    this is reported at lower confidence for a human to judge.

All of this is a direct read of response headers — no fuzzing, no baseline
comparison needed.

Safety
------
Only GET requests are issued, with a benign test ``Origin`` header. Nothing
is written or modified on the target.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, List, Optional, Set
from urllib.parse import urlparse

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc

logger = logging.getLogger(__name__)

# A fixed, recognisable attacker-origin — not resolved or contacted, it only
# needs to be distinct from the target's own origin so a *reflection* is
# unambiguous.
_ATTACKER_ORIGIN = "https://vortexdast-cors-attacker.invalid"
_NULL_ORIGIN = "null"

# Credentialed + reflected/wildcarded origin: full cross-origin account
# takeover of anything this session can read.
# AV:N / AC:L / PR:N / UI:N / S:C / C:H / I:N / A:N
_CVSS_VECTOR_CREDENTIALED = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="N", A="N"
)
_CVSS_SCORE_CREDENTIALED: float = cvss_calc(_CVSS_VECTOR_CREDENTIALED)

# Reflected/wildcarded origin without credentials: unauthenticated read
# exposure only — still waives the Same-Origin Policy, but can't act as the
# victim.
# AV:N / AC:L / PR:N / UI:N / S:C / C:L / I:N / A:N
_CVSS_VECTOR_UNCREDENTIALED = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="C", C="L", I="N", A="N"
)
_CVSS_SCORE_UNCREDENTIALED: float = cvss_calc(_CVSS_VECTOR_UNCREDENTIALED)


class CORSCheckModule(BaseScannerModule):
    """CORS misconfiguration detection via Origin-header reflection probing."""

    name: str = "cors_check"
    description: str = (
        "Detects CORS misconfigurations by sending a test Origin header and "
        "checking whether Access-Control-Allow-Origin reflects it (or sends "
        "'*') together with Access-Control-Allow-Credentials."
    )

    def __init__(self, requester: Any) -> None:
        super().__init__(requester)
        self._seen_lock = threading.Lock()
        self._seen: Set[str] = set()

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        key = _origin_path_key(endpoint.url)
        with self._seen_lock:
            if key in self._seen:
                return []
            self._seen.add(key)

        findings: List[Finding] = []
        for test_origin in (_ATTACKER_ORIGIN, _NULL_ORIGIN):
            finding = self._probe_origin(endpoint.url, test_origin)
            if finding:
                findings.append(finding)
        return findings

    def _probe_origin(self, url: str, test_origin: str) -> Optional[Finding]:
        resp, err = self.requester.get(url, headers={"Origin": test_origin})
        if err or resp is None:
            return None

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if not acao:
            return None
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        reflects = acao == test_origin
        wildcard = acao == "*"
        if not (reflects or wildcard):
            return None  # a fixed, specific allowlisted origin — not a misconfig

        return self._finding(url, test_origin, acao, acac)

    def _finding(self, url: str, test_origin: str, acao: str, acac: bool) -> Finding:
        logger.info(
            "⚡ CORS misconfig: %s | Origin=%s → ACAO=%s ACAC=%s",
            url, test_origin, acao, acac,
        )
        origin_desc = "a sandboxed/`null`-origin context" if test_origin == _NULL_ORIGIN else "an arbitrary attacker-controlled origin"

        if acac:
            severity, confidence = Severity.HIGH, Confidence.CERTAIN
            vector, score = _CVSS_VECTOR_CREDENTIALED, _CVSS_SCORE_CREDENTIALED
            impact = (
                "Because credentials are also allowed, a page served from "
                f"{origin_desc} can make an authenticated request (carrying the "
                "victim's cookies) and read the response — full cross-origin "
                "account takeover of anything this session can reach."
            )
        else:
            severity, confidence = Severity.MEDIUM, Confidence.TENTATIVE
            vector, score = _CVSS_VECTOR_UNCREDENTIALED, _CVSS_SCORE_UNCREDENTIALED
            impact = (
                "No credentials are allowed alongside it, so this waives the "
                "Same-Origin Policy for unauthenticated reads only — often "
                "intentional for a public API; confirm this endpoint carries "
                "no sensitive per-user data."
            )

        return Finding(
            title="CORS Misconfiguration — Origin Reflected/Wildcarded",
            severity=severity,
            confidence=confidence,
            url=url,
            parameter=None,
            payload=f"Origin: {test_origin}",
            evidence=(
                f"Sent 'Origin: {test_origin}'. Response: "
                f"'Access-Control-Allow-Origin: {acao}'"
                + (", 'Access-Control-Allow-Credentials: true'" if acac else "")
            ),
            description=(
                f"Sending '{test_origin}' as the Origin header got it reflected "
                f"back verbatim in Access-Control-Allow-Origin (or a literal "
                f"'*', offered to {origin_desc} either way). {impact}"
            ),
            remediation=(
                "Validate the Origin header against a server-side allowlist of "
                "known, trusted origins — never reflect the request's own "
                "Origin unconditionally, and never pair a wildcard/reflected "
                "origin with Access-Control-Allow-Credentials: true."
            ),
            cvss_vector=vector,
            cvss_score=score,
            extra={
                "test_origin": test_origin,
                "acao": acao,
                "acac": acac,
                "module": self.name,
            },
        )


def _origin_path_key(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
