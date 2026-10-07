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
import socket
import ssl
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
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
# Deprecated TLS protocols (TLS 1.0, TLS 1.1, SSLv3): RFC 8996 formally deprecated.
_CVSS_DEPRECATED_TLS = build_vector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="N")
# Insecure/weak ciphers (RC4, 3DES, <128-bit key):
_CVSS_WEAK_CIPHER = build_vector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="N", A="N")
# Invalid or untrusted TLS certificate:
_CVSS_INVALID_CERT = build_vector(AV="A", AC="H", PR="N", UI="R", S="U", C="H", I="H", A="N")

_WEAK_CIPHER_KEYWORDS = ("RC4", "3DES", "DES", "MD5", "EXPORT", "NULL", "ANON")
_DEPRECATED_PROTOCOLS = frozenset({"SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"})


@dataclass
class TLSInfo:
    """Captured TLS connection metadata from a raw socket handshake."""

    protocol: str
    cipher_name: str
    secret_bits: int
    cert_verified: bool
    cert_error: Optional[str] = None


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

        try:
            res = self.requester.get(endpoint.url)
            if not isinstance(res, tuple) or len(res) != 2:
                return findings
            resp, err = res
        except Exception:
            return findings
        if err or resp is None:
            return findings
        content_type = resp.headers.get("Content-Type", "")
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

        findings: List[Finding] = []

        host = parts.netloc.rsplit("@", 1)[-1]
        if parts.port is not None:
            host = host.rsplit(":", 1)[0]

        tls_host = parts.hostname or host.strip("[]")
        port = parts.port or 443
        findings.extend(self._inspect_tls(origin, tls_host, port))

        # Only default-port HTTPS has a predictable HTTP counterpart.
        if parts.port not in (None, 443):
            return findings

        http_url = f"http://{host}/"
        try:
            res = self.requester.get(http_url, allow_redirects=False)
            if not isinstance(res, tuple) or len(res) != 2:
                return findings
            resp, err = res
        except Exception:
            return findings
        if err or resp is None:
            return findings  # Port 80 closed or filtered — nothing to downgrade to.

        location = resp.headers.get("Location", "")
        if 300 <= resp.status_code < 400 and urljoin(http_url, location).lower().startswith("https://"):
            return findings

        detail = (
            f"redirects to non-HTTPS location {location!r}"
            if 300 <= resp.status_code < 400
            else f"responds with HTTP {resp.status_code} instead of redirecting"
        )
        findings.append(self._finding(
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
        ))
        return findings

    # ── TLS Protocol & Cipher Inspection ─────────────────────────────────────

    def _inspect_tls(self, origin: str, host: str, port: int) -> List[Finding]:
        """
        Probe the TLS endpoint using a raw handshake to inspect protocol version,
        negotiated cipher suite, and certificate verification.
        """
        findings: List[Finding] = []
        tls_info = self._probe_tls(host, port)
        if not isinstance(tls_info, TLSInfo):
            return findings

        # 1. Deprecated TLS protocol check
        proto_upper = tls_info.protocol.upper()
        if proto_upper in _DEPRECATED_PROTOCOLS:
            findings.append(self._finding(
                title=f"Deprecated TLS Protocol In Use ({tls_info.protocol})",
                severity=Severity.HIGH,
                vector=_CVSS_DEPRECATED_TLS,
                url=f"{origin}/",
                evidence=f"Negotiated protocol: {tls_info.protocol}",
                description=(
                    f"The server negotiated {tls_info.protocol} with the client. "
                    "Protocols older than TLS 1.2 are formally deprecated by RFC 8996 "
                    "due to lack of modern cipher support and known cryptographic attacks "
                    "(POODLE, BEAST, SWEET32)."
                ),
                remediation=(
                    "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 on the server. "
                    "Configure TLS 1.2 and TLS 1.3 as the only permitted protocols."
                ),
                scope="origin",
                extra={"protocol": tls_info.protocol, "cipher": tls_info.cipher_name},
            ))

        # 2. Insecure or weak cipher check
        cipher_upper = tls_info.cipher_name.upper()
        is_weak_name = any(kw in cipher_upper for kw in _WEAK_CIPHER_KEYWORDS)
        is_weak_bits = 0 < tls_info.secret_bits < 128
        if is_weak_name or is_weak_bits:
            reasons = []
            if is_weak_name:
                reasons.append("uses deprecated/broken algorithm")
            if is_weak_bits:
                reasons.append(f"insufficient key length ({tls_info.secret_bits} bits < 128)")
            findings.append(self._finding(
                title=f"Weak TLS Cipher Suite Negotiated ({tls_info.cipher_name})",
                severity=Severity.MEDIUM,
                vector=_CVSS_WEAK_CIPHER,
                url=f"{origin}/",
                evidence=f"Negotiated cipher: {tls_info.cipher_name} ({tls_info.secret_bits} bits) — {', '.join(reasons)}",
                description=(
                    f"The server agreed to use cipher suite '{tls_info.cipher_name}' ({tls_info.secret_bits} bits). "
                    "Legacy ciphers (such as RC4, 3DES, DES, or short key lengths) do not meet current "
                    "cryptographic standards and may allow on-path eavesdropping or plaintext recovery."
                ),
                remediation=(
                    "Configure modern AEAD cipher suites (e.g. ECDHE-ECDSA-AES128-GCM-SHA256, "
                    "ECDHE-RSA-AES128-GCM-SHA256, CHACHA20-POLY1305) and disable CBC, 3DES, and RC4 suites."
                ),
                scope="origin",
                extra={
                    "cipher": tls_info.cipher_name,
                    "bits": tls_info.secret_bits,
                    "protocol": tls_info.protocol,
                },
            ))

        # 3. Certificate verification failure
        if not tls_info.cert_verified and tls_info.cert_error:
            findings.append(self._finding(
                title="TLS Certificate Validation Failed",
                severity=Severity.MEDIUM,
                vector=_CVSS_INVALID_CERT,
                url=f"{origin}/",
                evidence=f"Certificate validation error: {tls_info.cert_error}",
                description=(
                    f"The TLS certificate presented by {host}:{port} could not be validated "
                    "against standard Certificate Authority trust stores. This may indicate an expired, "
                    "self-signed, or untrusted certificate, allowing Man-in-the-Middle attacks."
                ),
                remediation=(
                    "Obtain and install a valid TLS certificate from a trusted public Certificate Authority "
                    "(e.g., Let's Encrypt) matching the fully qualified domain name."
                ),
                scope="origin",
                extra={"cert_error": tls_info.cert_error},
            ))

        return findings

    def _probe_tls(self, host: str, port: int = 443) -> Optional[TLSInfo]:
        """
        Perform a raw TLS handshake to inspect protocol, cipher suite, and cert validity.
        In mock environments where requester is a mock, returns None unless
        a mock probe handler is attached.
        """
        # Guard: In mock test environments, don't open real TCP sockets.
        if type(self.requester).__name__ in ("MagicMock", "Mock") or getattr(self.requester, "_is_mock", False):
            probe_fn = getattr(self.requester, "probe_tls", None)
            if callable(probe_fn):
                res = probe_fn(host, port)
                if isinstance(res, TLSInfo):
                    return res
            return None

        cert_verified = False
        cert_error: Optional[str] = None
        protocol = "UNKNOWN"
        cipher_name = "UNKNOWN"
        secret_bits = 0

        # Attempt verified handshake
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=4.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    protocol = ssock.version() or "UNKNOWN"
                    c = ssock.cipher()
                    if c:
                        cipher_name, _, secret_bits = c
                    cert_verified = True
        except ssl.SSLCertVerificationError as exc:
            cert_error = str(exc)
        except (socket.error, OSError, ssl.SSLError) as exc:
            logger.debug("Verified TLS handshake failed for %s:%d: %s", host, port, exc)

        # If verification failed (or threw SSLCertVerificationError), attempt unverified
        # to still extract protocol version and cipher suite
        if not cert_verified:
            try:
                ctx_no_verify = ssl.create_default_context()
                ctx_no_verify.check_hostname = False
                ctx_no_verify.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=4.0) as sock:
                    with ctx_no_verify.wrap_socket(sock, server_hostname=host) as ssock:
                        protocol = ssock.version() or "UNKNOWN"
                        c = ssock.cipher()
                        if c:
                            cipher_name, _, secret_bits = c
            except (socket.error, OSError, ssl.SSLError) as exc:
                logger.debug("Unverified TLS handshake failed for %s:%d: %s", host, port, exc)
                if not cert_error:
                    return None

        if protocol == "UNKNOWN" and not cert_error:
            return None

        return TLSInfo(
            protocol=protocol,
            cipher_name=cipher_name,
            secret_bits=secret_bits,
            cert_verified=cert_verified,
            cert_error=cert_error,
        )

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
