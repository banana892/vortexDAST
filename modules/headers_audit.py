"""
VortexDAST – modules/headers_audit.py
────────────────────────────────────────────────────────────────────────────
Passive Security Headers Auditor.

Analyses the HTTP response headers captured by the crawler for missing or
misconfigured security controls.  This module performs NO active requests —
it works entirely from the ``response_headers`` dict already stored on each
:class:`~core.crawler.CrawledEndpoint`.

Performance — Origin Deduplication
------------------------------------
Security response headers (HSTS, CSP, X-Frame-Options, …) are almost always
set at the **web-server / reverse-proxy level** and are therefore **identical
across every page of the same origin** (scheme + host + port).  Re-evaluating
all six checks for every one of 50+ crawled sub-pages wastes time and
produces many duplicate findings.

``HeadersAuditModule`` therefore maintains a class-level
``_audited_origins: set[str]`` that is shared across all ``run()`` calls
within a single scan.  The first endpoint for each unique origin is fully
audited; subsequent endpoints for the same origin return ``[]`` immediately.

Cookie checks are **always** run per-endpoint because ``Set-Cookie`` headers
may differ between pages (e.g., login page sets a session cookie, home page
does not).

Checks Performed
----------------
1.  **Strict-Transport-Security** (HSTS)
2.  **Content-Security-Policy** (CSP)
3.  **X-Frame-Options** (Clickjacking)
4.  **X-Content-Type-Options**
5.  **Referrer-Policy**
6.  **Set-Cookie** flags (HttpOnly, Secure, SameSite) — always per-endpoint
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Internal constants
# ─────────────────────────────────────────────────────────────────────────────

_HSTS_MIN_MAX_AGE = 31_536_000

_PERMISSIVE_REFERRER_POLICIES = {
    "unsafe-url",
    "no-referrer-when-downgrade",
    "",
}

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 vectors for header audit findings
# ─────────────────────────────────────────────────────────────────────────────
# Each entry maps a finding title to a pre-computed (vector, score) tuple.
# Rationale comments follow each entry.
# Headers are all passive misconfigurations (no active exploit by themselves);
# they raise impact because they amplify other attack classes.

def _v(*, AV: str, AC: str, PR: str, UI: str, S: str,  # noqa: N802
       C: str, I: str, A: str) -> Tuple[str, float]:
    """Build a (vector_str, score) pair for the CVSS lookup table."""
    vec = build_vector(AV=AV, AC=AC, PR=PR, UI=UI, S=S, C=C, I=I, A=A)
    return vec, cvss_calc(vec)


_HEADER_CVSS: Dict[str, Tuple[str, float]] = {
    # ── HSTS ────────────────────────────────────────────────────────────────
    # Missing HSTS: network MitM (AV:A), high complexity, no priv, UI required
    # to intercept; confidentiality only (credential sniffing).
    # AV:A / AC:H / PR:N / UI:R / S:U / C:H / I:N / A:N  → 4.2 (MEDIUM)
    "Missing Strict-Transport-Security (HSTS) Header":
        _v(AV="A", AC="H", PR="N", UI="R", S="U", C="H", I="N", A="N"),
    # Short max-age: same as missing but lower impact (partial window).
    # AV:A / AC:H / PR:N / UI:R / S:U / C:L / I:N / A:N  → 2.6 (LOW)
    "Strict-Transport-Security max-age Too Short":
        _v(AV="A", AC="H", PR="N", UI="R", S="U", C="L", I="N", A="N"),
    # Missing max-age: same as short.
    "Strict-Transport-Security Missing max-age Directive":
        _v(AV="A", AC="H", PR="N", UI="R", S="U", C="L", I="N", A="N"),
    # Missing includeSubDomains: informational, low C only.
    # AV:N / AC:H / PR:N / UI:R / S:U / C:L / I:N / A:N  → 3.1 (LOW)
    "Strict-Transport-Security Missing includeSubDomains":
        _v(AV="N", AC="H", PR="N", UI="R", S="U", C="L", I="N", A="N"),

    # ── CSP ────────────────────────────────────────────────────────────────
    # Missing CSP: amplifies XSS (requires another vuln; UI required).
    # AV:N / AC:H / PR:N / UI:R / S:C / C:L / I:L / A:N  → 4.7 (MEDIUM)
    "Missing Content-Security-Policy (CSP) Header":
        _v(AV="N", AC="H", PR="N", UI="R", S="C", C="L", I="L", A="N"),
    # unsafe-inline: directly enables inline XSS when combined with injection.
    # AV:N / AC:L / PR:N / UI:R / S:C / C:L / I:L / A:N  → 6.1 (MEDIUM)
    "Content-Security-Policy Allows 'unsafe-inline'":
        _v(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
    # unsafe-eval: enables DOM XSS escalation; same vector.
    "Content-Security-Policy Allows 'unsafe-eval'":
        _v(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
    # Wildcard source: slightly lower impact (any origin, but AC still Low).
    # AV:N / AC:L / PR:N / UI:R / S:U / C:L / I:L / A:N  → 5.4 (MEDIUM)
    "Content-Security-Policy Contains Wildcard Source (*)":
        _v(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N"),

    # ── X-Frame-Options ───────────────────────────────────────────────────────
    # Missing XFO: clickjacking; UI required; integrity impact (user tricked).
    # AV:N / AC:L / PR:N / UI:R / S:U / C:N / I:L / A:N  → 4.3 (MEDIUM)
    "Missing X-Frame-Options Header":
        _v(AV="N", AC="L", PR="N", UI="R", S="U", C="N", I="L", A="N"),
    # Weak XFO value: same impact.
    "X-Frame-Options Has Weak or Invalid Value":
        _v(AV="N", AC="L", PR="N", UI="R", S="U", C="N", I="L", A="N"),

    # ── X-Content-Type-Options ────────────────────────────────────────────────
    # MIME sniffing: enables content-type confusion; AC:H (requires upload).
    # AV:N / AC:H / PR:N / UI:R / S:U / C:L / I:L / A:N  → 3.7 (LOW)
    "Missing X-Content-Type-Options Header":
        _v(AV="N", AC="H", PR="N", UI="R", S="U", C="L", I="L", A="N"),
    "X-Content-Type-Options Has Invalid Value":
        _v(AV="N", AC="H", PR="N", UI="R", S="U", C="L", I="L", A="N"),

    # ── Referrer-Policy ────────────────────────────────────────────────────────
    # Missing/permissive referrer: leaks URL tokens to 3rd parties (C:L).
    # AV:N / AC:L / PR:N / UI:R / S:U / C:L / I:N / A:N  → 4.3 (MEDIUM)
    "Missing Referrer-Policy Header":
        _v(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="N", A="N"),
    "Permissive Referrer-Policy Detected":
        _v(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="N", A="N"),

    # ── Cookie flags ─────────────────────────────────────────────────────────
    # Missing HttpOnly: JS can steal session cookies via XSS (needs XSS first).
    # AV:N / AC:H / PR:N / UI:R / S:U / C:H / I:N / A:N  → 5.3 (MEDIUM)
    "Cookie Missing HttpOnly Flag":
        _v(AV="N", AC="H", PR="N", UI="R", S="U", C="H", I="N", A="N"),
    # Missing Secure: cookie may travel over HTTP (MitM); AV:A.
    # AV:A / AC:H / PR:N / UI:N / S:U / C:H / I:N / A:N  → 5.3 (MEDIUM)
    "Cookie Missing Secure Flag":
        _v(AV="A", AC="H", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    # Missing SameSite: CSRF vector; integrity impact.
    # AV:N / AC:L / PR:N / UI:R / S:U / C:N / I:L / A:N  → 4.3 (MEDIUM)
    "Cookie Missing SameSite Attribute":
        _v(AV="N", AC="L", PR="N", UI="R", S="U", C="N", I="L", A="N"),
    # SameSite=None without Secure: cookie sent cross-site over HTTP.
    # AV:A / AC:L / PR:N / UI:N / S:U / C:H / I:N / A:N  → 6.5 (MEDIUM)
    "Cookie SameSite=None Without Secure Flag":
        _v(AV="A", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
}


def _header_cvss(title: str) -> Dict[str, Any]:
    """
    Return a dict of ``cvss_vector`` and ``cvss_score`` kwargs for a
    given finding title, ready to be unpacked into :class:`~modules.base.Finding`.

    Falls back to ``None`` values if the title is not in the lookup table
    (should not happen in practice, but guards against future regressions).
    """
    pair = _HEADER_CVSS.get(title)
    if pair is None:
        return {"cvss_vector": None, "cvss_score": None}
    return {"cvss_vector": pair[0], "cvss_score": pair[1]}



class HeadersAuditModule(BaseScannerModule):
    """
    Passively audits HTTP response headers for missing security controls.

    Deduplicates header checks at the **origin** (scheme + host + port) level
    so that each unique server is audited only once even when the crawler
    returns many pages from the same host.

    ``Set-Cookie`` checks are always evaluated per-endpoint because cookie
    headers differ between pages.

    Inherits from :class:`~modules.base.BaseScannerModule`.
    """

    name: str = "headers_audit"
    description: str = (
        "Passive analysis of HTTP security response headers and Set-Cookie flags. "
        "Deduplicates per-origin; cookie checks run on every endpoint."
    )

    def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kwargs)
        # Instance-level set so the audit state is scoped to one scan session.
        # We use an instance set (not class-level) so parallel test runs don't
        # bleed state into each other.
        self._audited_origins: Set[str] = set()

    # ─────────────────────────────────────────────────────────────────────────
    # Public entry point
    # ─────────────────────────────────────────────────────────────────────────

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        """
        Audit the response headers of a single crawled endpoint.

        Global header checks (HSTS, CSP, XFO, XCTO, Referrer-Policy) are
        skipped if this origin has already been audited in this session.
        Cookie checks always run.

        Parameters
        ----------
        endpoint : CrawledEndpoint
            A crawled page with its captured ``response_headers`` dict.

        Returns
        -------
        list[Finding]
            One :class:`Finding` per identified misconfiguration.
        """
        findings: List[Finding] = []
        headers = _CaseInsensitiveHeaders(endpoint.response_headers)
        url = endpoint.url

        # ── Cookie checks — always per-endpoint ───────────────────────────
        findings.extend(self._check_set_cookie(headers, url))

        # ── Global header checks — once per unique origin ─────────────────
        origin = _origin(url)
        if origin in self._audited_origins:
            logger.debug(
                "headers_audit: skipping global checks for %s (origin %s already audited)",
                url, origin,
            )
            return findings

        self._audited_origins.add(origin)
        logger.debug(
            "headers_audit: auditing global headers for origin %s via %s",
            origin, url,
        )

        findings.extend(self._check_hsts(headers, url))
        findings.extend(self._check_csp(headers, url))
        findings.extend(self._check_x_frame_options(headers, url))
        findings.extend(self._check_x_content_type_options(headers, url))
        findings.extend(self._check_referrer_policy(headers, url))

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # Individual header checks
    # ─────────────────────────────────────────────────────────────────────────

    def _check_hsts(
        self, headers: "_CaseInsensitiveHeaders", url: str
    ) -> List[Finding]:
        """Audit the ``Strict-Transport-Security`` header."""
        findings: List[Finding] = []

        if urlparse(url).scheme != "https":
            return findings

        hsts_value = headers.get("Strict-Transport-Security")

        if hsts_value is None:
            findings.append(
                Finding(
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=(
                        "The HTTPS endpoint does not set the Strict-Transport-Security "
                        "header. Without HSTS, browsers may allow HTTP downgrade attacks "
                        "(SSL-stripping) on subsequent visits."
                    ),
                    remediation=(
                        "Add: Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload"
                    ),
                    **_header_cvss("Missing Strict-Transport-Security (HSTS) Header"),

                    extra={"header": "Strict-Transport-Security"},
                )
            )
            return findings

        max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts_value, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < _HSTS_MIN_MAX_AGE:
                findings.append(
                    Finding(
                        title="Strict-Transport-Security max-age Too Short",
                        severity=Severity.LOW,
                        confidence=Confidence.CERTAIN,
                        url=url,
                        description=(
                            f"HSTS max-age is set to {max_age} seconds "
                            f"(< {_HSTS_MIN_MAX_AGE}). A short max-age limits HSTS "
                            "effectiveness and leaves a window for SSL-stripping attacks."
                        ),
                        remediation="Set max-age to at least 31536000 (1 year).",
                        evidence=hsts_value,
                        **_header_cvss("Strict-Transport-Security max-age Too Short"),

                        extra={"header": "Strict-Transport-Security", "max_age": max_age},
                    )
                )
        else:
            findings.append(
                Finding(
                    title="Strict-Transport-Security Missing max-age Directive",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description="HSTS header present but lacks a valid max-age directive.",
                    remediation="Ensure the header includes a valid max-age value.",
                    evidence=hsts_value,
                    **_header_cvss("Strict-Transport-Security Missing max-age Directive"),

                    extra={"header": "Strict-Transport-Security"},
                )
            )

        if "includesubdomains" not in hsts_value.lower():
            findings.append(
                Finding(
                    title="Strict-Transport-Security Missing includeSubDomains",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=(
                        "HSTS header does not include the ``includeSubDomains`` directive. "
                        "Subdomains remain accessible over HTTP and could be used as a "
                        "vector to attack the parent domain via cookie injection."
                    ),
                    remediation="Add ``includeSubDomains`` to the HSTS header.",
                    evidence=hsts_value,
                    **_header_cvss("Strict-Transport-Security Missing includeSubDomains"),

                    extra={"header": "Strict-Transport-Security"},
                )
            )

        return findings

    def _check_csp(
        self, headers: "_CaseInsensitiveHeaders", url: str
    ) -> List[Finding]:
        """Audit the ``Content-Security-Policy`` header."""
        findings: List[Finding] = []
        csp_value = headers.get("Content-Security-Policy")

        if csp_value is None:
            findings.append(
                Finding(
                    title="Missing Content-Security-Policy (CSP) Header",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=(
                        "No Content-Security-Policy header was detected. Without a CSP, "
                        "the browser has no instruction to block injected inline scripts, "
                        "which significantly increases the impact of any XSS vulnerability."
                    ),
                    remediation=(
                        "Define a restrictive CSP, e.g.:\n"
                        "Content-Security-Policy: default-src 'self'; "
                        "script-src 'self'; object-src 'none';"
                    ),
                    **_header_cvss("Missing Content-Security-Policy (CSP) Header"),

                    extra={"header": "Content-Security-Policy"},
                )
            )
            return findings

        csp_lower = csp_value.lower()

        if "'unsafe-inline'" in csp_lower:
            findings.append(
                Finding(
                    title="Content-Security-Policy Allows 'unsafe-inline'",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=(
                        "The CSP policy contains 'unsafe-inline', which permits the "
                        "execution of inline <script> and <style> blocks. This "
                        "effectively negates XSS protection for inline injection vectors."
                    ),
                    remediation=(
                        "Remove 'unsafe-inline' from script-src. Use nonces or hashes "
                        "for legitimate inline scripts instead."
                    ),
                    evidence=csp_value,
                    **_header_cvss("Content-Security-Policy Allows 'unsafe-inline'"),

                    extra={"header": "Content-Security-Policy", "weakness": "unsafe-inline"},
                )
            )

        if "'unsafe-eval'" in csp_lower:
            findings.append(
                Finding(
                    title="Content-Security-Policy Allows 'unsafe-eval'",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=(
                        "The CSP policy contains 'unsafe-eval', which permits the use "
                        "of eval(), new Function(), and similar dynamic code-execution "
                        "sinks. This enables DOM-based XSS escalation."
                    ),
                    remediation=(
                        "Remove 'unsafe-eval'. Refactor code to avoid dynamic "
                        "code-execution patterns."
                    ),
                    evidence=csp_value,
                    **_header_cvss("Content-Security-Policy Allows 'unsafe-eval'"),

                    extra={"header": "Content-Security-Policy", "weakness": "unsafe-eval"},
                )
            )

        if re.search(r"(default-src|script-src)\s+[^;]*\*", csp_lower):
            findings.append(
                Finding(
                    title="Content-Security-Policy Contains Wildcard Source (*)",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=(
                        "The CSP policy contains a wildcard (*) in a source directive, "
                        "allowing content to be loaded from any origin."
                    ),
                    remediation="Replace wildcard sources with explicit, trusted origins.",
                    evidence=csp_value,
                    **_header_cvss("Content-Security-Policy Contains Wildcard Source (*)"),

                    extra={"header": "Content-Security-Policy", "weakness": "wildcard"},
                )
            )

        return findings

    def _check_x_frame_options(
        self, headers: "_CaseInsensitiveHeaders", url: str
    ) -> List[Finding]:
        """Audit the ``X-Frame-Options`` header."""
        findings: List[Finding] = []
        xfo_value = headers.get("X-Frame-Options")

        if xfo_value is None:
            findings.append(
                Finding(
                    title="Missing X-Frame-Options Header",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=(
                        "The X-Frame-Options header is not set. Without this header, "
                        "attackers can embed this page inside an <iframe> to perform "
                        "clickjacking attacks."
                    ),
                    remediation=(
                        "Add: X-Frame-Options: DENY\n"
                        "Or use CSP: frame-ancestors 'none';"
                    ),
                    **_header_cvss("Missing X-Frame-Options Header"),

                    extra={"header": "X-Frame-Options"},
                )
            )
            return findings

        valid_values = {"deny", "sameorigin"}
        xfo_normalised = xfo_value.strip().lower()

        if xfo_normalised.startswith("allow-from") or xfo_normalised not in valid_values:
            findings.append(
                Finding(
                    title="X-Frame-Options Has Weak or Invalid Value",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=(
                        f"X-Frame-Options is set to '{xfo_value}'. "
                        "ALLOW-FROM is deprecated; only DENY or SAMEORIGIN are effective."
                    ),
                    remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                    evidence=xfo_value,
                    **_header_cvss("X-Frame-Options Has Weak or Invalid Value"),

                    extra={"header": "X-Frame-Options"},
                )
            )

        return findings

    def _check_x_content_type_options(
        self, headers: "_CaseInsensitiveHeaders", url: str
    ) -> List[Finding]:
        """Audit the ``X-Content-Type-Options`` header."""
        findings: List[Finding] = []
        xcto_value = headers.get("X-Content-Type-Options")

        if xcto_value is None:
            findings.append(
                Finding(
                    title="Missing X-Content-Type-Options Header",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=(
                        "The X-Content-Type-Options header is absent. Without 'nosniff', "
                        "browsers may MIME-sniff response content and execute files as "
                        "a different content type."
                    ),
                    remediation="Add: X-Content-Type-Options: nosniff",
                    **_header_cvss("Missing X-Content-Type-Options Header"),

                    extra={"header": "X-Content-Type-Options"},
                )
            )
            return findings

        if xcto_value.strip().lower() != "nosniff":
            findings.append(
                Finding(
                    title="X-Content-Type-Options Has Invalid Value",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=(
                        f"X-Content-Type-Options is set to '{xcto_value}' — the only "
                        "valid value is 'nosniff'."
                    ),
                    remediation="Set the header value to exactly 'nosniff'.",
                    evidence=xcto_value,
                    **_header_cvss("X-Content-Type-Options Has Invalid Value"),

                    extra={"header": "X-Content-Type-Options"},
                )
            )

        return findings

    def _check_referrer_policy(
        self, headers: "_CaseInsensitiveHeaders", url: str
    ) -> List[Finding]:
        """Audit the ``Referrer-Policy`` header."""
        findings: List[Finding] = []
        rp_value = headers.get("Referrer-Policy")

        if rp_value is None:
            findings.append(
                Finding(
                    title="Missing Referrer-Policy Header",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=(
                        "No Referrer-Policy header is set. Browsers may send the full "
                        "URL as a Referer header to third-party resources, potentially "
                        "leaking sensitive tokens."
                    ),
                    remediation=(
                        "Add: Referrer-Policy: strict-origin-when-cross-origin\n"
                        "Or use: no-referrer for the most restrictive behaviour."
                    ),
                    **_header_cvss("Missing Referrer-Policy Header"),

                    extra={"header": "Referrer-Policy"},
                )
            )
            return findings

        if rp_value.strip().lower() in _PERMISSIVE_REFERRER_POLICIES:
            findings.append(
                Finding(
                    title="Permissive Referrer-Policy Detected",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=(
                        f"Referrer-Policy is set to '{rp_value}', which sends the full "
                        "Referer URL to third-party origins."
                    ),
                    remediation="Use 'strict-origin-when-cross-origin' or stricter.",
                    evidence=rp_value,
                    **_header_cvss("Permissive Referrer-Policy Detected"),

                    extra={"header": "Referrer-Policy"},
                )
            )

        return findings

    def _check_set_cookie(
        self, headers: "_CaseInsensitiveHeaders", url: str
    ) -> List[Finding]:
        """
        Audit all ``Set-Cookie`` headers for missing HttpOnly, Secure, and
        SameSite security attributes.

        This check runs on **every** endpoint (not deduplicated by origin)
        because different pages may set different cookies.
        """
        findings: List[Finding] = []
        raw_cookies = headers.get_all("Set-Cookie")
        if not raw_cookies:
            return findings

        for raw_cookie in raw_cookies:
            cookie_name = raw_cookie.split("=")[0].strip()
            cookie_lower = raw_cookie.lower()

            if "httponly" not in cookie_lower:
                findings.append(
                    Finding(
                        title="Cookie Missing HttpOnly Flag",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CERTAIN,
                        url=url,
                        parameter=cookie_name,
                        description=(
                            f"The cookie '{cookie_name}' is set without the HttpOnly flag. "
                            "Client-side JavaScript can read this cookie, making it "
                            "accessible to XSS attacks."
                        ),
                        remediation=f"Add the HttpOnly attribute to the '{cookie_name}' cookie.",
                        evidence=raw_cookie[:200],
                        **_header_cvss("Cookie Missing HttpOnly Flag"),

                        extra={"cookie_name": cookie_name, "dedup_scope": "origin", "missing_flag": "HttpOnly"},
                    )
                )

            if "secure" not in cookie_lower:
                findings.append(
                    Finding(
                        title="Cookie Missing Secure Flag",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CERTAIN,
                        url=url,
                        parameter=cookie_name,
                        description=(
                            f"The cookie '{cookie_name}' is set without the Secure flag. "
                            "The cookie may be transmitted over unencrypted HTTP connections."
                        ),
                        remediation=f"Add the Secure attribute to the '{cookie_name}' cookie.",
                        evidence=raw_cookie[:200],
                        **_header_cvss("Cookie Missing Secure Flag"),

                        extra={"cookie_name": cookie_name, "dedup_scope": "origin", "missing_flag": "Secure"},
                    )
                )

            if "samesite" not in cookie_lower:
                findings.append(
                    Finding(
                        title="Cookie Missing SameSite Attribute",
                        severity=Severity.LOW,
                        confidence=Confidence.CERTAIN,
                        url=url,
                        parameter=cookie_name,
                        description=(
                            f"The cookie '{cookie_name}' has no SameSite attribute. "
                            "Without SameSite, the cookie is sent with cross-site "
                            "requests, increasing exposure to CSRF attacks."
                        ),
                        remediation=(
                            f"Add SameSite=Lax or SameSite=Strict to '{cookie_name}'."
                        ),
                        evidence=raw_cookie[:200],
                        **_header_cvss("Cookie Missing SameSite Attribute"),

                        extra={"cookie_name": cookie_name, "dedup_scope": "origin", "missing_flag": "SameSite"},
                    )
                )
            else:
                samesite_match = re.search(r"samesite\s*=\s*(\w+)", cookie_lower)
                if samesite_match and samesite_match.group(1) == "none":
                    if "secure" not in cookie_lower:
                        findings.append(
                            Finding(
                                title="Cookie SameSite=None Without Secure Flag",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.CERTAIN,
                                url=url,
                                parameter=cookie_name,
                                description=(
                                    f"Cookie '{cookie_name}' uses SameSite=None without "
                                    "the Secure attribute. Modern browsers will reject it."
                                ),
                                remediation=(
                                    "Set SameSite=Lax or SameSite=Strict, or add Secure "
                                    "when using SameSite=None."
                                ),
                                evidence=raw_cookie[:200],
                                **_header_cvss("Cookie SameSite=None Without Secure Flag"),

                                extra={
                                    "cookie_name": cookie_name,
                                    "dedup_scope": "origin",
                                    "weakness": "SameSite=None without Secure",
                                },
                            )
                        )

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────


def _origin(url: str) -> str:
    """
    Return the *origin* component of a URL: ``scheme://host[:port]``.

    Used to deduplicate header checks so each unique server is audited once.

    Examples
    --------
    >>> _origin("https://demo.testfire.net/bank/main.aspx")
    'https://demo.testfire.net'
    >>> _origin("http://demo.testfire.net:8080/page")
    'http://demo.testfire.net:8080'
    """
    parsed = urlparse(url)
    if parsed.port:
        return f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
    return f"{parsed.scheme}://{parsed.hostname}"


class _CaseInsensitiveHeaders:
    """
    Thin wrapper around a plain ``dict`` of HTTP headers that provides
    case-insensitive key lookup and multi-value retrieval for Set-Cookie.

    HTTP header names are case-insensitive per RFC 7230.
    """

    def __init__(self, headers: Dict[str, str]) -> None:
        self._data: Dict[str, str] = {k.lower(): v for k, v in headers.items()}

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Case-insensitive header lookup."""
        return self._data.get(key.lower(), default)

    def get_all(self, key: str) -> List[str]:
        """
        Return individual header values for headers that may appear multiple
        times (e.g., Set-Cookie).  urllib3 joins duplicates with ``\\n``.
        """
        raw = self._data.get(key.lower())
        if raw is None:
            return []
        return [v.strip() for v in raw.split("\n") if v.strip()]

    def __len__(self) -> int:
        return len(self._data)
