"""
VortexDAST – modules/transport_check.py
────────────────────────────────────────────────────────────────────────────
Passive transport-security audit (OWASP A02: Cryptographic Failures).

Per page:
  * Password fields served over HTTP, or submitted to an ``http://`` action.
  * Mixed content on HTTPS pages — active (script, stylesheet, iframe,
    object, form action) vs. passive (img, audio, video, source).

Per origin (once):
  * Site served over plain HTTP.
  * HTTPS site whose HTTP counterpart serves content instead of redirecting
    to HTTPS (default ports only).
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc
from core.requester import Requester

logger = logging.getLogger(__name__)

# Credentials readable by a network attacker on the path.
_CVSS_CREDENTIALS = build_vector(AV="A", AC="L", PR="N", UI="R", S="U", C="H", I="N", A="N")
# Active mixed content / cleartext site: MitM can read and tamper with the page.
_CVSS_ACTIVE = build_vector(AV="A", AC="H", PR="N", UI="R", S="U", C="L", I="L", A="N")
# Passive mixed content / missing redirect: limited tampering or leakage.
_CVSS_PASSIVE = build_vector(AV="A", AC="H", PR="N", UI="R", S="U", C="L", I="N", A="N")

_ACTIVE_ATTRS: List[Tuple[str, str]] = [
    ("script", "src"),
    ("iframe", "src"),
    ("frame", "src"),
    ("object", "data"),
    ("embed", "src"),
    ("form", "action"),
]
_PASSIVE_ATTRS: List[Tuple[str, str]] = [
    ("img", "src"),
    ("audio", "src"),
    ("video", "src"),
    ("source", "src"),
]
_MAX_LISTED = 10


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


class TransportCheckModule(BaseScannerModule):
    """Passive HTTPS / mixed-content / cleartext-credential audit."""

    name: str = "transport_check"
    description: str = (
        "Flags cleartext HTTP, password forms over HTTP, mixed content on HTTPS "
        "pages, and HTTP endpoints that don't redirect to HTTPS."
    )

    def __init__(self, requester: Requester) -> None:
        super().__init__(requester)
        self._audited_origins: Set[str] = set()
        self._lock = threading.Lock()

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        findings: List[Finding] = []
        scheme = urlsplit(endpoint.url).scheme.lower()
        if scheme not in ("http", "https"):
            return findings

        origin = _origin(endpoint.url)
        with self._lock:
            first_visit = origin not in self._audited_origins
            self._audited_origins.add(origin)
        if first_visit:
            findings.extend(self._origin_checks(endpoint.url, scheme))

        resp, err = self.requester.get(endpoint.url)
        if err or resp is None:
            return findings
        content_type = (resp.headers or {}).get("Content-Type", "")
        if content_type and "html" not in content_type.lower():
            return findings

        soup = BeautifulSoup(resp.text or "", "html.parser")
        findings.extend(self._credential_checks(endpoint.url, scheme, soup))
        if scheme == "https":
            findings.extend(self._mixed_content_checks(endpoint.url, soup))
        return findings

    # ── Origin-level ─────────────────────────────────────────────────────────

    def _origin_checks(self, url: str, scheme: str) -> List[Finding]:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"

        if scheme == "http":
            return [self._finding(
                title="Site Served Over Unencrypted HTTP",
                severity=Severity.MEDIUM,
                vector=_CVSS_ACTIVE,
                url=origin + "/",
                evidence=f"Scanned origin uses the http:// scheme: {origin}",
                description=(
                    "Pages on this origin are delivered without TLS. Anyone on the network path "
                    "can read and modify page content, cookies, and submitted data."
                ),
                remediation=(
                    "Serve the site exclusively over HTTPS, redirect all HTTP requests to HTTPS "
                    "with a 301, and enable HSTS."
                ),
                scope="origin",
            )]

        # Only default-port HTTPS has a predictable HTTP counterpart.
        if parts.port not in (None, 443):
            return []
        host = parts.netloc.rsplit("@", 1)[-1]
        if parts.port is not None:
            host = host.rsplit(":", 1)[0]
        http_url = f"http://{host}/"
        resp, err = self.requester.get(http_url, allow_redirects=False)
        if err or resp is None:
            return []  # Port 80 closed or filtered — nothing to downgrade to.

        location = (resp.headers or {}).get("Location", "")
        if 300 <= resp.status_code < 400 and urljoin(http_url, location).lower().startswith("https://"):
            return []

        detail = (
            f"redirects to non-HTTPS location {location!r}"
            if 300 <= resp.status_code < 400
            else f"responds with HTTP {resp.status_code} instead of redirecting"
        )
        return [self._finding(
            title="HTTP Endpoint Does Not Redirect to HTTPS",
            severity=Severity.LOW,
            vector=_CVSS_PASSIVE,
            url=http_url,
            evidence=f"GET {http_url} {detail}.",
            description=(
                "The site is available over HTTPS, but its plain-HTTP counterpart does not "
                "redirect to it. Users who type the bare domain or follow old links stay on "
                "an unencrypted connection, enabling SSL-stripping attacks."
            ),
            remediation="Return a 301 redirect from every HTTP URL to its HTTPS equivalent and enable HSTS.",
            scope="origin",
        )]

    # ── Page-level ───────────────────────────────────────────────────────────

    def _credential_checks(self, url: str, scheme: str, soup: Any) -> List[Finding]:
        findings: List[Finding] = []
        for form in soup.find_all("form"):
            if not form.find("input", attrs={"type": lambda t: t and t.lower() == "password"}):
                continue
            action = urljoin(url, form.get("action") or url)
            action_scheme = urlsplit(action).scheme.lower()
            if scheme == "https" and action_scheme != "http":
                continue

            where = (
                "is served over HTTP"
                if scheme == "http"
                else f"is served over HTTPS but submits to {action!r}"
            )
            findings.append(self._finding(
                title="Password Form Transmitted Over Unencrypted HTTP",
                severity=Severity.HIGH,
                vector=_CVSS_CREDENTIALS,
                url=url,
                parameter=f"form[action={action}]",
                evidence=f"A form containing a password field {where}.",
                description=(
                    "Credentials entered into this form travel in cleartext and can be captured "
                    "by anyone on the network path (public Wi-Fi, compromised routers, proxies)."
                ),
                remediation="Serve the login page and its form action exclusively over HTTPS.",
                scope="origin",
            ))
        return findings

    def _mixed_content_checks(self, url: str, soup: Any) -> List[Finding]:
        findings: List[Finding] = []
        for attrs, severity, vector, kind in (
            (_ACTIVE_ATTRS, Severity.MEDIUM, _CVSS_ACTIVE, "Active"),
            (_PASSIVE_ATTRS, Severity.LOW, _CVSS_PASSIVE, "Passive"),
        ):
            resources = self._insecure_resources(url, soup, attrs)
            if kind == "Active":
                resources += [
                    href for href in self._insecure_stylesheets(url, soup) if href not in resources
                ]
            if not resources:
                continue

            listed = ", ".join(resources[:_MAX_LISTED])
            more = f" (+{len(resources) - _MAX_LISTED} more)" if len(resources) > _MAX_LISTED else ""
            findings.append(self._finding(
                title=f"{kind} Mixed Content on HTTPS Page",
                severity=severity,
                vector=vector,
                url=url,
                evidence=f"{len(resources)} resource(s) loaded over HTTP: {listed}{more}",
                description=(
                    "This HTTPS page loads resources over plain HTTP. "
                    + (
                        "Scripts, stylesheets, frames, and form submissions loaded this way can be "
                        "rewritten in transit, giving a network attacker control of the page."
                        if kind == "Active"
                        else "Media loaded this way can be observed or swapped in transit."
                    )
                ),
                remediation=(
                    "Load every subresource over HTTPS (or protocol-relative to the page), and add "
                    "'Content-Security-Policy: upgrade-insecure-requests' as a safety net."
                ),
                extra={"insecure_resources": resources},
            ))
        return findings

    @staticmethod
    def _insecure_resources(url: str, soup: Any, attrs: List[Tuple[str, str]]) -> List[str]:
        found: List[str] = []
        for tag, attr in attrs:
            for el in soup.find_all(tag):
                value = el.get(attr)
                if not value:
                    continue
                absolute = urljoin(url, value.strip())
                if urlsplit(absolute).scheme.lower() == "http" and absolute not in found:
                    found.append(absolute)
        return found

    @staticmethod
    def _insecure_stylesheets(url: str, soup: Any) -> List[str]:
        found: List[str] = []
        for el in soup.find_all("link", href=True):
            rel = [r.lower() for r in (el.get("rel") or [])]
            if "stylesheet" not in rel:
                continue
            absolute = urljoin(url, el["href"].strip())
            if urlsplit(absolute).scheme.lower() == "http":
                found.append(absolute)
        return found

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _finding(
        self,
        *,
        title: str,
        severity: Severity,
        vector: str,
        url: str,
        evidence: str,
        description: str,
        remediation: str,
        parameter: Optional[str] = None,
        scope: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        meta: Dict[str, Any] = {"module": self.name, **(extra or {})}
        if scope:
            meta["dedup_scope"] = scope
        return Finding(
            title=title,
            severity=severity,
            confidence=Confidence.CERTAIN,
            url=url,
            parameter=parameter,
            evidence=evidence,
            description=description,
            remediation=remediation,
            cvss_vector=vector,
            cvss_score=cvss_calc(vector),
            extra=meta,
        )
