"""
VortexDAST – modules/dir_fuzzer.py
────────────────────────────────────────────────────────────────────────────
Wordlist Path & Sensitive File Discovery Module.

Detection Strategy
------------------
1. Load candidate administrative, configuration, and sensitive path suffixes
   from ``payloads/common_paths.json``.
2. Extract the target's base origin (``scheme://netloc``) from the crawled
   endpoint URL.
3. Origin Deduplication: Probe each unique web origin once per scan session.
4. Soft-404 Baseline Diffing:
   - Request a randomised non-existent path (e.g. ``/vortex_404_check_<uuid>``)
     to establish the baseline response (HTTP status, body length, content).
   - If candidate paths return HTTP 200 on servers with custom 404 handlers,
     suppress false positives via length comparison (within 5% / 50 bytes)
     and detection regex verification.
5. Emits findings categorized by severity (e.g. ``.env`` as HIGH,
   ``robots.txt`` as INFORMATIONAL) with calculated CVSS v3.1 vectors and scores.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import uuid
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple
from urllib.parse import urlparse

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc
from core.requester import Requester

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_COMMON_PATHS_PATH = os.path.join(_PAYLOADS_DIR, "common_paths.json")

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 vectors
# ─────────────────────────────────────────────────────────────────────────────

# HIGH — Sensitive credentials, config, or VCS source exposure (.env, .git/HEAD)
# AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:N / A:N  → 7.5
_CVSS_VECTOR_HIGH = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"
)
_CVSS_SCORE_HIGH: float = cvss_calc(_CVSS_VECTOR_HIGH)

# MEDIUM — Administrative panels, exposed Swagger/API schemas (C:L / I:N)
# AV:N / AC:L / PR:N / UI:N / S:U / C:L / I:N / A:N  → 5.3
_CVSS_VECTOR_MEDIUM = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"
)
_CVSS_SCORE_MEDIUM: float = cvss_calc(_CVSS_VECTOR_MEDIUM)

# LOW — Low-sensitivity diagnostics or protected resources returning 401/403
# AV:N / AC:H / PR:N / UI:N / S:U / C:L / I:N / A:N  → 3.7
_CVSS_VECTOR_LOW = build_vector(
    AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"
)
_CVSS_SCORE_LOW: float = cvss_calc(_CVSS_VECTOR_LOW)

# INFORMATIONAL — Public discovery (robots.txt, sitemap.xml, security.txt)
# AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:N  → 0.0
_CVSS_VECTOR_INFO = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N"
)
_CVSS_SCORE_INFO: float = cvss_calc(_CVSS_VECTOR_INFO)


_SEVERITY_MAP: Dict[str, Tuple[Severity, str, float]] = {
    "critical": (Severity.CRITICAL, _CVSS_VECTOR_HIGH, _CVSS_SCORE_HIGH),
    "high": (Severity.HIGH, _CVSS_VECTOR_HIGH, _CVSS_SCORE_HIGH),
    "medium": (Severity.MEDIUM, _CVSS_VECTOR_MEDIUM, _CVSS_SCORE_MEDIUM),
    "low": (Severity.LOW, _CVSS_VECTOR_LOW, _CVSS_SCORE_LOW),
    "informational": (Severity.INFORMATIONAL, _CVSS_VECTOR_INFO, _CVSS_SCORE_INFO),
}

# Generic soft-404 error strings
_GENERIC_404_PATTERNS = [
    re.compile(r"(?i)404\s+not\s+found"),
    re.compile(r"(?i)page\s+not\s+found"),
    re.compile(r"(?i)cannot\s+get\s+/"),
    re.compile(r"(?i)the\s+requested\s+url\s+was\s+not\s+found"),
    re.compile(r"(?i)error\s+404"),
    re.compile(r"(?i)oops!"),
]


class _PathEntry:
    """Compiled candidate path entry for directory fuzzing."""

    __slots__ = ("path", "category", "severity_str", "description", "regex")

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.path: str = raw["path"]
        self.category: str = raw.get("category", "general")
        self.severity_str: str = raw.get("severity", "informational").lower()
        self.description: str = raw.get("description", "")
        regex_str = raw.get("content_regex")
        self.regex: Optional[Pattern[str]] = (
            re.compile(regex_str) if regex_str else None
        )


class DirFuzzerModule(BaseScannerModule):
    """
    Wordlist Path & Sensitive File Discovery Module.

    Passively identifies the base host URL, probes common administrative,
    configuration, and sensitive paths, and validates responses using
    soft-404 baseline diffing.
    """

    name: str = "dir_fuzzer"
    description: str = (
        "Discovers administrative portals, backup files, configuration leaks, "
        "and API documentation schemas using a curated wordlist with soft-404 suppression."
    )

    def __init__(
        self,
        requester: Requester,
        payloads_path: Optional[str] = None,
    ) -> None:
        super().__init__(requester)
        self._payloads_path = payloads_path or _COMMON_PATHS_PATH
        self._paths: List[_PathEntry] = []
        self._audited_origins: Set[str] = set()
        self._origins_lock = threading.Lock()
        self._load_payloads()

    def _load_payloads(self) -> None:
        """Load and compile candidate paths from JSON."""
        try:
            with open(self._payloads_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.error("dir_fuzzer: Failed to load payload file: %s", exc)
            return

        raw_paths = data.get("paths", [])
        self._paths = [_PathEntry(p) for p in raw_paths]
        logger.debug("dir_fuzzer: loaded %d candidate paths", len(self._paths))

    def _get_origin(self, url: str) -> str:
        """Extract scheme://netloc from URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        """
        Execute path discovery against the origin of the given endpoint.

        Probing is deduplicated at the origin level so that multi-page crawls
        do not repeat wordlist requests against the same server.
        """
        if not self._paths:
            return []

        origin = self._get_origin(endpoint.url)
        if not origin:
            return []
        with self._origins_lock:
            if origin in self._audited_origins:
                return []
            self._audited_origins.add(origin)
        findings: List[Finding] = []

        # ── 1. Soft-404 Baseline Probe ──────────────────────────────────────
        probe_404_url = f"{origin}/vortex_404_check_{uuid.uuid4().hex[:8]}"
        baseline_resp, baseline_err = self.requester.get(probe_404_url)

        baseline_status = baseline_resp.status_code if baseline_resp else 404
        baseline_body = baseline_resp.text if baseline_resp else ""
        baseline_len = len(baseline_body)

        logger.debug(
            "dir_fuzzer: origin=%s baseline_404_status=%d baseline_len=%d",
            origin,
            baseline_status,
            baseline_len,
        )

        # ── 2. Probe Candidate Paths ────────────────────────────────────────
        def _probe(idx: int, entry: _PathEntry) -> Tuple[int, _PathEntry, str, Any]:
            target_url = f"{origin}/{entry.path.lstrip('/')}"
            resp, err = self.requester.get(target_url)
            return idx, entry, target_url, None if err else resp

        results = self.requester.dispatch_concurrent(
            [lambda i=i, e=e: _probe(i, e) for i, e in enumerate(self._paths)]
        )
        results.sort(key=lambda r: r[0])

        for _idx, entry, target_url, resp in results:
            if resp is None:
                continue

            status = resp.status_code
            body = resp.text or ""
            content_len = len(body)

            # Skip standard 404s and server errors
            if status == 404 or status >= 500:
                continue

            # ── 3. Soft-404 & Content Verification ──────────────────────────
            regex_matched = bool(entry.regex and entry.regex.search(body))

            # Catch-all handlers (custom 200 pages, blanket 401/403, login
            # redirects) answer every path the same way as the random probe.
            if status == baseline_status and not regex_matched:
                len_diff = abs(content_len - baseline_len)
                if len_diff < 50 or (baseline_len > 0 and len_diff / baseline_len < 0.05):
                    continue

            if status == 200:
                if baseline_status == 200 and not regex_matched and any(
                    pat.search(body) for pat in _GENERIC_404_PATTERNS
                ):
                    continue

                if entry.regex and not regex_matched:
                    continue

            # ── 4. Generate Finding ─────────────────────────────────────────
            severity_key = entry.severity_str
            if status in (401, 403):
                # Accessible but restricted
                if severity_key in ("high", "critical"):
                    severity_key = "medium"
                elif severity_key == "medium":
                    severity_key = "low"
                else:
                    severity_key = "informational"

            sev_enum, cvss_vec, cvss_sc = _SEVERITY_MAP.get(
                severity_key,
                (Severity.INFORMATIONAL, _CVSS_VECTOR_INFO, _CVSS_SCORE_INFO),
            )

            title = f"Discovered Sensitive Path / File: {entry.path}"
            if entry.category == "admin":
                title = f"Discovered Administrative Portal: {entry.path}"
            elif entry.category == "api":
                title = f"Discovered API Schema / Documentation: {entry.path}"
            elif entry.category == "backup":
                title = f"Discovered Backup / Archive File: {entry.path}"
            elif entry.category == "vcs":
                title = f"Exposed Version Control Artifact: {entry.path}"
            elif entry.category == "config":
                title = f"Exposed Configuration File: {entry.path}"

            evidence_snippet = body[:200].replace("\r", "").replace("\n", " ").strip()
            evidence = (
                f"HTTP {status} ({len(resp.content)} bytes) returned for path '{entry.path}'. "
                f"Response snippet: {evidence_snippet}"
            )

            finding = Finding(
                title=title,
                severity=sev_enum,
                confidence=Confidence.CERTAIN if regex_matched else Confidence.FIRM,
                url=target_url,
                parameter=entry.path,
                payload=entry.path,
                evidence=evidence,
                description=(
                    f"The endpoint '{entry.path}' was discovered on the server ({entry.description}). "
                    f"Status Code: HTTP {status}."
                ),
                remediation=(
                    "Restrict public access to administrative portals, backup files, and internal configuration "
                    "endpoints using web server access rules, IP allowlisting, or strong authentication."
                ),
                cvss_vector=cvss_vec,
                cvss_score=cvss_sc,
                extra={
                    "category": entry.category,
                    "status_code": status,
                    "content_length": len(resp.content),
                    "module": self.name,
                },
            )
            findings.append(finding)

        return findings
