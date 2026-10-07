"""
VortexDAST – modules/param_fuzzer.py
────────────────────────────────────────────────────────────────────────────
Hidden Parameter Discovery & Fuzzing Module.

Detection Strategy
------------------
1. Load candidate parameter names from ``payloads/common_params.json``.
2. Fetch a baseline response for the crawled endpoint URL to record:
   - Baseline HTTP status code
   - Baseline response body text and byte length
3. For each candidate parameter:
   - Inject benign test values (e.g. ``?debug=1``, ``?test=true``, ``?admin=1``).
   - Issue the GET request with the parameter appended.
   - Diff the response against baseline to identify:
     * Status code anomalies (e.g. 403 → 200 bypass or 200 → 500 error).
     * Reflection of the injected parameter value.
     * Significant response body length shifts (> 15% and > 50 bytes).
     * Debug indicators, stack traces, or verbose framework profiling output.
4. Generates findings categorized by anomaly severity.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc
from core.requester import Requester

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_COMMON_PARAMS_PATH = os.path.join(_PAYLOADS_DIR, "common_params.json")

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 vectors
# ─────────────────────────────────────────────────────────────────────────────

# MEDIUM — Hidden parameter triggers authentication bypass or debug mode
# AV:N / AC:L / PR:N / UI:N / S:U / C:L / I:N / A:N  → 5.3
_CVSS_VECTOR_MEDIUM = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"
)
_CVSS_SCORE_MEDIUM: float = cvss_calc(_CVSS_VECTOR_MEDIUM)

# LOW — Anomalous response or server error triggered by hidden parameter
# AV:N / AC:H / PR:N / UI:N / S:U / C:L / I:N / A:N  → 3.7
_CVSS_VECTOR_LOW = build_vector(
    AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"
)
_CVSS_SCORE_LOW: float = cvss_calc(_CVSS_VECTOR_LOW)

# INFORMATIONAL — Parameter accepted or reflected with benign response change
# AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:N  → 0.0
_CVSS_VECTOR_INFO = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N"
)
_CVSS_SCORE_INFO: float = cvss_calc(_CVSS_VECTOR_INFO)

# Debug and error indicators
_DEBUG_PATTERNS = [
    re.compile(r"(?i)traceback\s+\(most\s+recent\s+call\s+last\)"),
    re.compile(r"(?i)stack\s*trace:"),
    re.compile(r"(?i)debug\s+(?:mode|toolbar|information)"),
    re.compile(r"(?i)sql\s*query:"),
    re.compile(r"(?i)call\s+stack:"),
    re.compile(r"(?i)(?:var_dump|print_r)\s*\("),
    re.compile(r"(?i)django\.core\.exceptions"),
    re.compile(r"(?i)werkzeug\.exceptions"),
]


class _ParamEntry:
    """Candidate parameter configuration."""

    __slots__ = ("name", "category", "description", "test_values")

    def __init__(self, raw: Dict[str, Any], default_values: List[str]) -> None:
        self.name: str = raw["name"]
        self.category: str = raw.get("category", "general")
        self.description: str = raw.get("description", "")
        self.test_values: List[str] = raw.get("test_values") or default_values


class ParamFuzzerModule(BaseScannerModule):
    """
    Hidden Parameter Discovery & Fuzzing Module.

    Probes discovered endpoints with candidate hidden GET parameters using
    benign test values and performs baseline response diffing.
    """

    name: str = "param_fuzzer"
    description: str = (
        "Probes endpoints with candidate hidden GET/POST parameters using benign test "
        "values and baseline diffing to identify unadvertised application parameters."
    )

    def __init__(
        self,
        requester: Requester,
        payloads_path: Optional[str] = None,
    ) -> None:
        super().__init__(requester)
        self._payloads_path = payloads_path or _COMMON_PARAMS_PATH
        self._params: List[_ParamEntry] = []
        self._default_values: List[str] = ["1", "true", "test"]
        self._audited_pairs: Set[Tuple[str, str]] = set()
        self._pairs_lock = threading.Lock()
        self._load_payloads()

    def _load_payloads(self) -> None:
        """Load candidate parameter names and default probe values."""
        try:
            with open(self._payloads_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.error("param_fuzzer: Failed to load payload file: %s", exc)
            return

        self._default_values = data.get("default_test_values", ["1", "true", "test"])
        raw_params = data.get("params", [])
        self._params = [_ParamEntry(p, self._default_values) for p in raw_params]
        logger.debug("param_fuzzer: loaded %d candidate parameters", len(self._params))

    def _build_fuzzed_url(self, url: str, param_name: str, value: str) -> str:
        """Append or update a single query parameter on the given URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [value]
        # urlencode with doseq to preserve lists
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        """
        Probe the endpoint with candidate hidden parameters and diff responses.
        """
        if not self._params:
            return []

        # ── 1. Fetch Baseline Response ──────────────────────────────────────
        baseline_resp, baseline_err = self.requester.get(endpoint.url)
        if baseline_err or baseline_resp is None:
            logger.debug(
                "param_fuzzer: baseline fetch failed for %s: %s",
                endpoint.url,
                baseline_err,
            )
            return []

        baseline_status = baseline_resp.status_code
        baseline_body = baseline_resp.text or ""
        baseline_len = len(baseline_body)

        # A second fetch measures how much the page varies on its own
        # (CSRF tokens, timestamps, rotating content).
        repeat_resp, _ = self.requester.get(endpoint.url)
        length_jitter = (
            abs(len(repeat_resp.text or "") - baseline_len) if repeat_resp is not None else 0
        )

        # Candidate parameters to probe (exclude already known query params)
        existing_params = set(endpoint.query_params.keys())
        parsed_url = urlparse(endpoint.url)
        base_endpoint_path = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        findings: List[Finding] = []

        # ── 2. Probe Candidate Parameters ───────────────────────────────────
        for entry in self._params:
            if entry.name in existing_params:
                continue

            audit_key = (base_endpoint_path, entry.name)
            with self._pairs_lock:
                if audit_key in self._audited_pairs:
                    continue
                self._audited_pairs.add(audit_key)

            # Use primary test value
            test_val = entry.test_values[0] if entry.test_values else "1"
            fuzzed_url = self._build_fuzzed_url(endpoint.url, entry.name, test_val)

            resp, err = self.requester.get(fuzzed_url)
            if err or resp is None:
                continue

            status = resp.status_code
            body = resp.text or ""
            body_len = len(body)

            # ── 3. Anomaly Analysis ─────────────────────────────────────────
            anomalies: List[str] = []
            severity = Severity.INFORMATIONAL
            cvss_vec = _CVSS_VECTOR_INFO
            cvss_sc = _CVSS_SCORE_INFO

            # Check for Status Code Anomaly
            if baseline_status in (401, 403, 404) and status in (200, 302):
                anomalies.append(
                    f"Status code changed from HTTP {baseline_status} to HTTP {status} (potential access bypass)"
                )
                severity = Severity.MEDIUM
                cvss_vec = _CVSS_VECTOR_MEDIUM
                cvss_sc = _CVSS_SCORE_MEDIUM
            elif baseline_status == 200 and status >= 500:
                anomalies.append(
                    f"Parameter triggered internal server error (HTTP {status})"
                )
                severity = Severity.LOW
                cvss_vec = _CVSS_VECTOR_LOW
                cvss_sc = _CVSS_SCORE_LOW

            # Check for Debug / Stack Trace Output
            matched_debug_snippets: List[str] = []
            for pat in _DEBUG_PATTERNS:
                m = pat.search(body)
                if m and not pat.search(baseline_body):
                    matched_debug_snippets.append(m.group(0))

            if matched_debug_snippets:
                anomalies.append(
                    f"Exposed debug/stack trace in response body ({', '.join(matched_debug_snippets[:2])})"
                )
                severity = Severity.MEDIUM
                cvss_vec = _CVSS_VECTOR_MEDIUM
                cvss_sc = _CVSS_SCORE_MEDIUM

            # Check for Parameter Reflection
            if (
                test_val
                and test_val in body
                and test_val not in baseline_body
                and len(test_val) >= 2
            ):
                anomalies.append(
                    f"Injected parameter value '{test_val}' reflected in response body"
                )

            # Check for Significant Body Delta
            if baseline_status == 200 and status == 200:
                len_diff = abs(body_len - baseline_len)
                if (
                    baseline_len > 0
                    and len_diff > max(50, 2 * length_jitter)
                    and (len_diff / baseline_len) > 0.15
                ):
                    anomalies.append(
                        f"Significant response body length delta ({len_diff:+d} bytes, {(len_diff/baseline_len)*100:.1f}%)"
                    )

            if not anomalies:
                continue

            # ── 4. Generate Finding ─────────────────────────────────────────
            title = f"Discovered Hidden Parameter: '{entry.name}'"
            if entry.category == "debug" or severity == Severity.MEDIUM:
                title = f"Debug / Administrative Parameter Accepted: '{entry.name}'"

            evidence = (
                f"Probing parameter '{entry.name}={test_val}' triggered anomalous response: "
                + "; ".join(anomalies)
            )

            finding = Finding(
                title=title,
                severity=severity,
                confidence=(
                    Confidence.FIRM if severity == Severity.MEDIUM else Confidence.TENTATIVE
                ),
                url=fuzzed_url,
                parameter=entry.name,
                payload=test_val,
                evidence=evidence,
                description=(
                    f"The parameter '{entry.name}' was detected as accepted or processed by the endpoint "
                    f"'{endpoint.url}'. Category: {entry.category}. ({entry.description})."
                ),
                remediation=(
                    "Review unadvertised or legacy debug parameters. Disable development/debug flags in production "
                    "and validate that all accepted parameters enforce strict access control."
                ),
                cvss_vector=cvss_vec,
                cvss_score=cvss_sc,
                extra={
                    "parameter": entry.name,
                    "category": entry.category,
                    "anomalies": anomalies,
                    "baseline_status": baseline_status,
                    "response_status": status,
                    "module": self.name,
                },
            )
            findings.append(finding)

        return findings
