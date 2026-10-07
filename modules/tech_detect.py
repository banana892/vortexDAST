"""
VortexDAST – modules/tech_detect.py
────────────────────────────────────────────────────────────────────────────
Tech-Stack Fingerprinting Module.

Detection Strategy
------------------
1. Load signature regexes from ``payloads/tech_signatures.json``.
2. Passively inspect:
   - HTTP Response Headers (``Server``, ``X-Powered-By``, ``X-AspNet-Version``, etc.)
   - Session / Application Cookies (``PHPSESSID``, ``JSESSIONID``, ``csrftoken``, etc.)
   - HTML ``<meta>`` tags (e.g. ``<meta name="generator">``)
   - HTML ``<script src="...">`` references (React, Vue, Angular, jQuery, Next.js, etc.)
   - DOM markers and HTML elements (``data-reactroot``, ``ng-version``, ``__NEXT_DATA__``)
3. Origin-level deduplication: Each discovered technology is reported once per unique
   origin (``scheme://netloc``).
4. Generates INFORMATIONAL findings (CVSS 0.0) detailing detected technologies.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc
from core.requester import Requester

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_TECH_SIGNATURES_PATH = os.path.join(_PAYLOADS_DIR, "tech_signatures.json")

# CVSS v3.1 vector for informational fingerprint findings (0.0)
_CVSS_VECTOR_INFO = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N"
)
_CVSS_SCORE_INFO: float = cvss_calc(_CVSS_VECTOR_INFO)


class _HeaderSig:
    __slots__ = ("tech", "category", "header", "regex")

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.tech: str = raw["tech"]
        self.category: str = raw.get("category", "General")
        self.header: str = raw["header"].lower()
        self.regex: Pattern[str] = re.compile(raw["regex"])


class _CookieSig:
    __slots__ = ("tech", "category", "name_regex")

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.tech: str = raw["tech"]
        self.category: str = raw.get("category", "General")
        self.name_regex: Pattern[str] = re.compile(raw["name_regex"])


class _ScriptSig:
    __slots__ = ("tech", "category", "src_regex")

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.tech: str = raw["tech"]
        self.category: str = raw.get("category", "General")
        self.src_regex: Pattern[str] = re.compile(raw["src_regex"])


class _DomSig:
    __slots__ = ("tech", "category", "sig_type", "attribute", "regex")

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.tech: str = raw["tech"]
        self.category: str = raw.get("category", "General")
        self.sig_type: str = raw.get("type", "html")
        self.attribute: Optional[str] = raw.get("attribute")
        self.regex: Pattern[str] = re.compile(raw["regex"])


class TechDetectModule(BaseScannerModule):
    """
    Technology Stack Fingerprinting Module.

    Inspects HTTP response headers, cookies, script tags, and DOM markers
    against a signature database to identify web servers, programming
    languages, and frontend/backend frameworks.
    """

    name: str = "tech_detect"
    description: str = (
        "Fingerprints web servers, backend frameworks, and frontend libraries from "
        "HTTP headers, session cookies, script tags, and DOM markers."
    )

    def __init__(
        self,
        requester: Requester,
        payloads_path: Optional[str] = None,
    ) -> None:
        super().__init__(requester)
        self._payloads_path = payloads_path or _TECH_SIGNATURES_PATH
        self._header_sigs: List[_HeaderSig] = []
        self._cookie_sigs: List[_CookieSig] = []
        self._script_sigs: List[_ScriptSig] = []
        self._dom_sigs: List[_DomSig] = []
        self._detected_technologies: Set[Tuple[str, str]] = set()
        self._detected_lock = threading.Lock()
        self._load_signatures()

    def _load_signatures(self) -> None:
        """Load and compile technology signatures from JSON."""
        try:
            with open(self._payloads_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.error("tech_detect: Failed to load signatures: %s", exc)
            return

        self._header_sigs = [_HeaderSig(s) for s in data.get("headers", [])]
        self._cookie_sigs = [_CookieSig(s) for s in data.get("cookies", [])]
        self._script_sigs = [_ScriptSig(s) for s in data.get("scripts", [])]
        self._dom_sigs = [_DomSig(s) for s in data.get("dom_markers", [])]
        logger.debug(
            "tech_detect: loaded %d header, %d cookie, %d script, %d dom signatures",
            len(self._header_sigs),
            len(self._cookie_sigs),
            len(self._script_sigs),
            len(self._dom_sigs),
        )

    def _claim(self, key: Tuple[str, str]) -> bool:
        """Atomically mark (origin, tech) as reported; False if already claimed."""
        with self._detected_lock:
            if key in self._detected_technologies:
                return False
            self._detected_technologies.add(key)
            return True

    def _get_origin(self, url: str) -> str:
        """Extract scheme://netloc from URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        """
        Execute passive technology detection against the endpoint.
        """
        if not (self._header_sigs or self._cookie_sigs or self._script_sigs or self._dom_sigs):
            return []

        origin = self._get_origin(endpoint.url)
        findings: List[Finding] = []

        # ── 1. Fetch Page for Complete Headers and Body ─────────────────────
        resp, err = self.requester.get(endpoint.url)
        body = resp.text if resp is not None else ""
        headers = resp.headers if resp is not None else endpoint.response_headers

        # Normalise headers to lowercase keys
        lower_headers: Dict[str, str] = {k.lower(): v for k, v in headers.items()}

        # ── 2. Header Matching ──────────────────────────────────────────────
        for sig in self._header_sigs:
            header_val = lower_headers.get(sig.header)
            if not header_val:
                continue

            match = sig.regex.search(header_val)
            if match:
                dedup_key = (origin, sig.tech)
                if not self._claim(dedup_key):
                    continue

                version = match.group(1) if match.groups() and match.group(1) else None
                tech_display = f"{sig.tech} {version}".strip() if version else sig.tech
                evidence = f"Header '{sig.header}: {header_val}' matched pattern '{sig.regex.pattern}'"

                findings.append(
                    self._create_finding(
                        endpoint_url=endpoint.url,
                        tech_name=tech_display,
                        category=sig.category,
                        evidence=evidence,
                        match_type="HTTP Header",
                        version=version,
                    )
                )

        # ── 3. Cookie Matching ──────────────────────────────────────────────
        cookie_names: Set[str] = set()
        if resp is not None:
            cookie_names.update(resp.cookies.keys())
        set_cookie_header = lower_headers.get("set-cookie", "")
        if set_cookie_header:
            for part in set_cookie_header.split(";"):
                if "=" in part:
                    cookie_names.add(part.split("=")[0].strip())

        for cookie_name in cookie_names:
            for sig in self._cookie_sigs:
                if sig.name_regex.search(cookie_name):
                    dedup_key = (origin, sig.tech)
                    if not self._claim(dedup_key):
                        continue

                    evidence = f"Cookie '{cookie_name}' matched pattern '{sig.name_regex.pattern}'"
                    findings.append(
                        self._create_finding(
                            endpoint_url=endpoint.url,
                            tech_name=sig.tech,
                            category=sig.category,
                            evidence=evidence,
                            match_type="Session Cookie",
                            version=None,
                        )
                    )

        # ── 4. Script and DOM Matching (if body is present) ─────────────────
        if body:
            soup = BeautifulSoup(body, "html.parser")

            # Script tag sources
            script_srcs = [
                script.get("src", "")
                for script in soup.find_all("script")
                if script.get("src")
            ]
            for src in script_srcs:
                for sig in self._script_sigs:
                    match = sig.src_regex.search(src)
                    if match:
                        dedup_key = (origin, sig.tech)
                        if not self._claim(dedup_key):
                            continue

                        version = match.group(1) if match.groups() and match.group(1) else None
                        tech_display = f"{sig.tech} {version}".strip() if version else sig.tech
                        evidence = f"<script src='{src}'> matched pattern '{sig.src_regex.pattern}'"

                        findings.append(
                            self._create_finding(
                                endpoint_url=endpoint.url,
                                tech_name=tech_display,
                                category=sig.category,
                                evidence=evidence,
                                match_type="Script Tag",
                                version=version,
                            )
                        )

            # DOM & Meta tags
            for sig in self._dom_sigs:
                if sig.sig_type == "meta" and sig.attribute:
                    meta_tags = soup.find_all("meta", attrs={"name": sig.attribute})
                    meta_tags += soup.find_all("meta", attrs={"property": sig.attribute})
                    for meta in meta_tags:
                        content = meta.get("content", "")
                        match = sig.regex.search(content)
                        if match:
                            dedup_key = (origin, sig.tech)
                            if not self._claim(dedup_key):
                                continue

                            version = match.group(1) if match.groups() and match.group(1) else None
                            tech_display = f"{sig.tech} {version}".strip() if version else sig.tech
                            evidence = f"<meta name='{sig.attribute}' content='{content}'> matched '{sig.regex.pattern}'"

                            findings.append(
                                self._create_finding(
                                    endpoint_url=endpoint.url,
                                    tech_name=tech_display,
                                    category=sig.category,
                                    evidence=evidence,
                                    match_type="Meta Tag",
                                    version=version,
                                )
                            )
                elif sig.sig_type == "html":
                    match = sig.regex.search(body)
                    if match:
                        dedup_key = (origin, sig.tech)
                        if not self._claim(dedup_key):
                            continue

                        version = match.group(1) if match.groups() and match.group(1) else None
                        tech_display = f"{sig.tech} {version}".strip() if version else sig.tech
                        evidence = f"DOM body matched pattern '{sig.regex.pattern}'"

                        findings.append(
                            self._create_finding(
                                endpoint_url=endpoint.url,
                                tech_name=tech_display,
                                category=sig.category,
                                evidence=evidence,
                                match_type="DOM Marker",
                                version=version,
                            )
                        )

        return findings

    def _create_finding(
        self,
        endpoint_url: str,
        tech_name: str,
        category: str,
        evidence: str,
        match_type: str,
        version: Optional[str],
    ) -> Finding:
        """Construct a standardized informational Finding for a detected technology."""
        return Finding(
            title=f"Technology Fingerprint: {tech_name} ({category})",
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.CERTAIN,
            url=endpoint_url,
            parameter=None,
            payload=None,
            evidence=evidence,
            description=(
                f"Identified '{tech_name}' ({category}) active on '{endpoint_url}' via {match_type}."
            ),
            remediation=(
                "Ensure server tokens and framework identification headers (e.g. Server, X-Powered-By) "
                "are suppressed in production environments to minimize information disclosure."
            ),
            cvss_vector=_CVSS_VECTOR_INFO,
            cvss_score=_CVSS_SCORE_INFO,
            extra={
                "technology": tech_name,
                "category": category,
                "match_type": match_type,
                "version": version,
                "module": self.name,
            },
        )
