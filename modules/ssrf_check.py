"""
VortexDAST – modules/ssrf_check.py
────────────────────────────────────────────────────────────────────────────
Server-Side Request Forgery (SSRF) Heuristic Detection Module.

Detection Strategy
------------------
1.  Load loopback probe URLs and URL-parameter keyword list from
    ``payloads/ssrf_probes.json``.
2.  **Candidate parameter identification** — filter all discovered GET query
    parameters and POST form fields whose *name* fuzzy-matches one of the
    SSRF-indicative keywords (e.g. ``url``, ``dest``, ``redirect``, ``src``).
3.  For each candidate parameter:
      a. Fetch a **baseline** response (original value, original URL) to
         record the status code, body length, and response time.
      b. Substitute the parameter value with each loopback/internal probe URL.
      c. Issue the fuzzed request and analyse the result using three signals:

         **Signal 1 — Status code change**
           A shift from a baseline 2xx/3xx to a different status code
           (especially 200, 500, 302 to loopback) may indicate the server
           fetched the internal target.  Baseline 4xx/5xx responses are
           skipped (false-positive suppression).

         **Signal 2 — Response timing differential**
           If the fuzzed request is significantly slower than the baseline
           (> ``_TIMING_DELTA_THRESHOLD_S`` seconds), the server may be
           attempting a network connection to the injected target, introducing
           latency before timing out.

         **Signal 3 — Loopback content markers in response body**
           Check the response body for strings that would only appear if the
           server returned internal service content (e.g. ``ami-id``,
           ``computeMetadata``, loopback IP strings, AWS/GCP metadata keys).

4.  Each triggered signal combination determines the finding severity:
      - Body marker matched   → HIGH
      - Status changed + slow → MEDIUM
      - Either alone          → LOW

False-Positive Suppression
--------------------------
*   Baseline 4xx/5xx responses are skipped entirely.
*   Timing-only signals require a delta of at least ``_TIMING_DELTA_THRESHOLD_S``
    seconds (default 2.5 s) to reduce noise from normal latency variation.
*   Body-marker matching is conservative: only well-known internal-service
    strings are matched (not generic error text).
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urlparse

from .base import BaseScannerModule, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc
from core.parser import ParsedForm

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_SSRF_PROBES_PATH = os.path.join(_PAYLOADS_DIR, "ssrf_probes.json")

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 vectors for SSRF finding severities
# ─────────────────────────────────────────────────────────────────────────────
# HIGH: body marker confirmed  – loopback content returned in response
#   AV:N / AC:L / PR:N / UI:N / S:C / C:H / I:H / A:N  → 9.6
_CVSS_VECTOR_SSRF_HIGH = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"
)
_CVSS_SCORE_SSRF_HIGH: float = cvss_calc(_CVSS_VECTOR_SSRF_HIGH)  # 9.6

# MEDIUM: status code changed + slow response – probable SSRF, unconfirmed
#   AV:N / AC:H / PR:N / UI:N / S:C / C:L / I:L / A:N  → 5.4
_CVSS_VECTOR_SSRF_MEDIUM = build_vector(
    AV="N", AC="H", PR="N", UI="N", S="C", C="L", I="L", A="N"
)
_CVSS_SCORE_SSRF_MEDIUM: float = cvss_calc(_CVSS_VECTOR_SSRF_MEDIUM)  # 5.4

# LOW: single weak signal (status change only OR timing only)
#   AV:N / AC:H / PR:N / UI:N / S:U / C:L / I:N / A:N  → 3.7
_CVSS_VECTOR_SSRF_LOW = build_vector(
    AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"
)
_CVSS_SCORE_SSRF_LOW: float = cvss_calc(_CVSS_VECTOR_SSRF_LOW)  # 3.7

# Severity → (vector, score) lookup used in Finding() construction.
_SSRF_CVSS: Dict[Severity, Tuple[str, float]] = {
    Severity.HIGH:   (_CVSS_VECTOR_SSRF_HIGH,   _CVSS_SCORE_SSRF_HIGH),
    Severity.MEDIUM: (_CVSS_VECTOR_SSRF_MEDIUM, _CVSS_SCORE_SSRF_MEDIUM),
    Severity.LOW:    (_CVSS_VECTOR_SSRF_LOW,    _CVSS_SCORE_SSRF_LOW),
}

# Minimum response-time delta (seconds) to treat as a timing-based signal.
_TIMING_DELTA_THRESHOLD_S: float = 2.5

# Strings in the response body that strongly suggest the server returned
# internal/loopback service content.  Kept conservative to minimise FPs.
_BODY_MARKERS: List[str] = [
    "ami-id",
    "instance-id",
    "computeMetadata",
    "meta-data",
    "169.254.169.254",
    "127.0.0.1",
    "::1",
    "localhost",
    "internal server",
    "aws_access_key_id",
    "aws_secret_access_key",
    "iam/security-credentials",
]


# ─────────────────────────────────────────────────────────────────────────────
# Internal types
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class _BaselineResult:
    """Captured baseline HTTP response data for a single parameter."""

    status_code: int
    body: str
    elapsed_s: float  # Wall-clock response time in seconds.


# ─────────────────────────────────────────────────────────────────────────────
# SSRF Check Module
# ─────────────────────────────────────────────────────────────────────────────


class SSRFCheckModule(BaseScannerModule):
    """
    Heuristic SSRF detection via loopback/internal URL injection.

    Identifies URL-like parameter candidates and probes them with safe
    loopback targets, analysing status codes, response timing, and body
    content for indicators of server-side request initiation.

    Inherits from :class:`~modules.base.BaseScannerModule`.
    """

    name: str = "ssrf_check"
    description: str = (
        "Detects Server-Side Request Forgery by injecting benign loopback "
        "URLs into candidate parameters and analysing status-code changes, "
        "response timing deltas, and internal-service body markers."
    )

    def __init__(
        self,
        requester: Any,
        payloads_path: Optional[str] = None,
        timing_threshold_s: float = _TIMING_DELTA_THRESHOLD_S,
    ) -> None:
        """
        Parameters
        ----------
        requester : Requester
            Shared HTTP session from the orchestrator.
        payloads_path : str | None
            Override path to ``ssrf_probes.json``.
        timing_threshold_s : float
            Minimum response-time delta (seconds) to emit a timing-based signal.
        """
        super().__init__(requester)
        path = payloads_path or _SSRF_PROBES_PATH
        self._keyword_set, self._loopback_probes = _load_ssrf_probes(path)
        self._timing_threshold = timing_threshold_s

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        """
        Probe all SSRF-candidate parameters on the endpoint.

        Parameters
        ----------
        endpoint : CrawledEndpoint
            A crawled page with its URL query parameters and forms.

        Returns
        -------
        list[Finding]
            One finding per confirmed or suspected SSRF vector.
        """
        findings: List[Finding] = []

        if not self._loopback_probes:
            logger.warning("ssrf_check: no probes loaded — skipping %s", endpoint.url)
            return findings

        # ── GET parameters (endpoint's own URL) ───────────────────────────
        candidate_get_params = self._filter_candidates(endpoint.query_params)
        if candidate_get_params:
            findings.extend(
                self._fuzz_get_params(endpoint.url, endpoint.query_params, candidate_get_params)
            )

        # ── GET parameters from discovered links ───────────────────────────
        for link in endpoint.links:
            candidates = self._filter_candidates(link.query_params)
            if candidates:
                findings.extend(
                    self._fuzz_get_params(link.url, link.query_params, candidates)
                )

        # ── POST form fields ───────────────────────────────────────────────
        for form in endpoint.forms:
            form_candidates = self._filter_form_candidates(form)
            if form_candidates:
                findings.extend(self._fuzz_form(form, form_candidates))

        return findings

    # ── Candidate identification ──────────────────────────────────────────────

    def _filter_candidates(
        self, params: Dict[str, List[str]]
    ) -> Set[str]:
        """
        Return the subset of parameter *names* that match SSRF-indicative
        keywords (case-insensitive substring match).
        """
        candidates: Set[str] = set()
        for param_name in params:
            if self._is_ssrf_candidate(param_name):
                candidates.add(param_name)
        return candidates

    def _filter_form_candidates(self, form: ParsedForm) -> Set[str]:
        """Return field names from a form that are SSRF-candidate parameters."""
        return {
            f.name for f in form.fields if self._is_ssrf_candidate(f.name)
        }

    def _is_ssrf_candidate(self, param_name: str) -> bool:
        """
        Return True if ``param_name`` is an SSRF-indicative parameter name.

        Uses both exact keyword matching and substring containment so that
        variants like ``redirect_url``, ``next_url``, or ``src_url`` are
        caught alongside exact matches like ``url`` or ``dest``.
        """
        lower = param_name.lower()
        # Exact match
        if lower in self._keyword_set:
            return True
        # Substring containment — catches url_param, redirect_to, img_url, etc.
        for keyword in self._keyword_set:
            if keyword in lower:
                return True
        return False

    # ── GET parameter fuzzing ─────────────────────────────────────────────────

    def _fuzz_get_params(
        self,
        url: str,
        all_params: Dict[str, List[str]],
        candidate_names: Set[str],
    ) -> List[Finding]:
        """Inject SSRF probes into each identified candidate GET parameter."""
        findings: List[Finding] = []
        base_params: Dict[str, str] = {k: v[0] for k, v in all_params.items() if v}

        for target_param in candidate_names:
            original_value = base_params.get(target_param, "")

            # ── Baseline ──────────────────────────────────────────────────
            baseline = self._fetch_get_baseline(url, base_params)
            if baseline is None:
                continue
            # Skip parameters where the baseline itself is an error response.
            if baseline.status_code >= 400:
                logger.debug(
                    "ssrf: baseline %d for %s param=%s — skipping",
                    baseline.status_code, url, target_param,
                )
                continue

            # ── Probe injection ───────────────────────────────────────────
            for probe in self._loopback_probes:
                fuzzed = dict(base_params)
                fuzzed[target_param] = probe["value"]

                parsed = urlparse(url)
                fuzzed_url = parsed._replace(query=urlencode(fuzzed)).geturl()

                finding = self._probe_and_analyse(
                    fuzzed_url=fuzzed_url,
                    original_value=original_value,
                    baseline=baseline,
                    probe=probe,
                    parameter=target_param,
                    method="GET",
                    fetch_fn=lambda u: self._timed_get(u),
                )
                if finding:
                    findings.append(finding)

        return findings

    # ── POST form fuzzing ─────────────────────────────────────────────────────

    def _fuzz_form(
        self,
        form: ParsedForm,
        candidate_names: Set[str],
    ) -> List[Finding]:
        """Inject SSRF probes into SSRF-candidate fields of a POST form."""
        findings: List[Finding] = []
        base_body: Dict[str, str] = {f.name: f.default_value for f in form.fields}

        for target_field in candidate_names:
            original_value = base_body.get(target_field, "")

            # ── Baseline POST ─────────────────────────────────────────────
            baseline = self._fetch_post_baseline(form.action_url, base_body)
            if baseline is None:
                continue
            if baseline.status_code >= 400:
                logger.debug(
                    "ssrf: POST baseline %d for %s field=%s — skipping",
                    baseline.status_code, form.action_url, target_field,
                )
                continue

            # ── Probe injection ───────────────────────────────────────────
            for probe in self._loopback_probes:
                fuzzed_body = dict(base_body)
                fuzzed_body[target_field] = probe["value"]

                finding = self._probe_and_analyse_post(
                    url=form.action_url,
                    fuzzed_body=fuzzed_body,
                    original_value=original_value,
                    baseline=baseline,
                    probe=probe,
                    parameter=target_field,
                )
                if finding:
                    findings.append(finding)

        return findings

    # ── Core analysis ─────────────────────────────────────────────────────────

    def _probe_and_analyse(
        self,
        fuzzed_url: str,
        original_value: str,
        baseline: _BaselineResult,
        probe: Dict[str, Any],
        parameter: str,
        method: str,
        fetch_fn: Any,
    ) -> Optional[Finding]:
        """
        Issue the fuzzed GET request and evaluate all three SSRF signals.
        """
        fuzzed_body, fuzzed_status, fuzzed_elapsed = fetch_fn(fuzzed_url)
        if fuzzed_status == 0:  # request failed
            return None

        return self._evaluate_signals(
            url=fuzzed_url,
            fuzzed_body=fuzzed_body,
            fuzzed_status=fuzzed_status,
            fuzzed_elapsed=fuzzed_elapsed,
            baseline=baseline,
            probe=probe,
            parameter=parameter,
            method=method,
        )

    def _probe_and_analyse_post(
        self,
        url: str,
        fuzzed_body: Dict[str, str],
        original_value: str,
        baseline: _BaselineResult,
        probe: Dict[str, Any],
        parameter: str,
    ) -> Optional[Finding]:
        """Issue the fuzzed POST request and evaluate all three SSRF signals."""
        body_text, status, elapsed = self._timed_post(url, fuzzed_body)
        if status == 0:
            return None

        return self._evaluate_signals(
            url=url,
            fuzzed_body=body_text,
            fuzzed_status=status,
            fuzzed_elapsed=elapsed,
            baseline=baseline,
            probe=probe,
            parameter=parameter,
            method="POST",
        )

    def _evaluate_signals(
        self,
        url: str,
        fuzzed_body: str,
        fuzzed_status: int,
        fuzzed_elapsed: float,
        baseline: _BaselineResult,
        probe: Dict[str, Any],
        parameter: str,
        method: str,
    ) -> Optional[Finding]:
        """
        Apply all three SSRF detection signals and return a Finding if any fire.

        Signal priority (highest first):
          1. Body markers → HIGH
          2. Status change + timing delta → MEDIUM
          3. Status change only → LOW
          4. Timing delta only → LOW
        """
        # Signal 1: Body marker
        matched_marker = self._check_body_markers(fuzzed_body)

        # Signal 2: Status code change
        status_changed = (fuzzed_status != baseline.status_code)

        # Signal 3: Timing delta
        timing_delta = fuzzed_elapsed - baseline.elapsed_s
        timing_fired = timing_delta >= self._timing_threshold

        # Nothing triggered.
        if not matched_marker and not status_changed and not timing_fired:
            return None

        # Determine severity based on signal combination.
        if matched_marker:
            severity = Severity.HIGH
            signal_description = (
                f"A loopback content marker was detected in the response body: "
                f"'{matched_marker}'. This strongly indicates the server fetched "
                f"the injected internal URL and returned its content."
            )
        elif status_changed and timing_fired:
            severity = Severity.MEDIUM
            signal_description = (
                f"The HTTP status code changed from {baseline.status_code} to "
                f"{fuzzed_status} AND the response was {timing_delta:.2f}s slower "
                f"than the baseline ({baseline.elapsed_s:.2f}s → {fuzzed_elapsed:.2f}s). "
                "Both signals together suggest the server attempted an outbound "
                "connection to the injected loopback target."
            )
        elif status_changed:
            severity = Severity.LOW
            signal_description = (
                f"The HTTP status code changed from {baseline.status_code} to "
                f"{fuzzed_status} after injecting the loopback probe. This may "
                "indicate the server attempted to resolve the injected URL."
            )
        else:  # timing only
            severity = Severity.LOW
            signal_description = (
                f"The response was {timing_delta:.2f}s slower than the baseline "
                f"({baseline.elapsed_s:.2f}s → {fuzzed_elapsed:.2f}s) after injecting "
                "the loopback URL. Unusual latency can indicate a backend connection "
                "attempt to the injected target."
            )

        evidence_snippet = (fuzzed_body[:300] + " […]") if len(fuzzed_body) > 300 else fuzzed_body

        logger.info(
            "⚡ SSRF signal: %s | param=%s | probe=%s | severity=%s",
            url, parameter, probe["value"], severity.value,
        )

        _cvss_vector, _cvss_score = _SSRF_CVSS.get(
            severity, (_CVSS_VECTOR_SSRF_LOW, _CVSS_SCORE_SSRF_LOW)
        )

        return Finding(
            title=f"Potential SSRF — {probe['description']}",
            severity=severity,
            url=url,
            parameter=parameter,
            payload=probe["value"],
            evidence=evidence_snippet,
            description=(
                f"Injecting the loopback probe '{probe['value']}' into the "
                f"'{parameter}' parameter via {method} produced indicators of "
                f"server-side request initiation.\n\n{signal_description}"
            ),
            remediation=(
                "Implement a strict server-side allowlist of permitted destination "
                "URLs/IPs. Reject or sanitise parameters that accept user-supplied "
                "URLs. Block outbound requests to loopback addresses (127.0.0.0/8, "
                "::1), link-local ranges (169.254.0.0/16), and private RFC-1918 "
                "ranges at the network layer. Disable unnecessary URL-fetching "
                "functionality and enforce metadata endpoint blocking on cloud hosts "
                "(IMDSv2 on AWS, metadata server firewall rules on GCP)."
            ),
            cvss_vector=_cvss_vector,
            cvss_score=_cvss_score,
            extra={
                "probe_id": probe.get("id"),
                "probe_value": probe["value"],
                "baseline_status": baseline.status_code,
                "fuzzed_status": fuzzed_status,
                "timing_delta_s": round(timing_delta, 3),
                "body_marker": matched_marker,
                "method": method,
                "module": self.name,
            },
        )

    # ── Signal helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _check_body_markers(body: str) -> Optional[str]:
        """
        Scan the response body for loopback/internal-service content markers.

        Returns the first matched marker string, or None.
        """
        body_lower = body.lower()
        for marker in _BODY_MARKERS:
            if marker.lower() in body_lower:
                return marker
        return None

    # ── Timed request helpers ─────────────────────────────────────────────────

    def _timed_get(self, url: str) -> Tuple[str, int, float]:
        """
        Issue a GET request and return (body, status_code, elapsed_seconds).
        Returns ("", 0, 0.0) on failure.
        """
        t0 = time.monotonic()
        response, error = self.requester.get(url)
        elapsed = time.monotonic() - t0

        if error or response is None:
            logger.debug("ssrf timed_get failed for %s: %s", url, error)
            return "", 0, 0.0
        return response.text, response.status_code, elapsed

    def _timed_post(
        self, url: str, data: Dict[str, str]
    ) -> Tuple[str, int, float]:
        """
        Issue a POST request and return (body, status_code, elapsed_seconds).
        Returns ("", 0, 0.0) on failure.
        """
        t0 = time.monotonic()
        response, error = self.requester.post(url, data=data)
        elapsed = time.monotonic() - t0

        if error or response is None:
            logger.debug("ssrf timed_post failed for %s: %s", url, error)
            return "", 0, 0.0
        return response.text, response.status_code, elapsed

    # ── Baseline fetchers ─────────────────────────────────────────────────────

    def _fetch_get_baseline(
        self, url: str, params: Dict[str, str]
    ) -> Optional[_BaselineResult]:
        """Fetch the original GET response for baseline capture."""
        parsed = urlparse(url)
        baseline_url = parsed._replace(query=urlencode(params)).geturl()
        body, status, elapsed = self._timed_get(baseline_url)
        if status == 0:
            return None
        return _BaselineResult(status_code=status, body=body, elapsed_s=elapsed)

    def _fetch_post_baseline(
        self, url: str, data: Dict[str, str]
    ) -> Optional[_BaselineResult]:
        """Fetch the original POST response for baseline capture."""
        body, status, elapsed = self._timed_post(url, data)
        if status == 0:
            return None
        return _BaselineResult(status_code=status, body=body, elapsed_s=elapsed)


# ─────────────────────────────────────────────────────────────────────────────
# Payload loader
# ─────────────────────────────────────────────────────────────────────────────


def _load_ssrf_probes(
    path: str,
) -> Tuple[Set[str], List[Dict[str, Any]]]:
    """
    Load SSRF probe definitions from JSON.

    Returns
    -------
    (keyword_set, loopback_probes)
        ``keyword_set``     – lower-cased parameter keyword strings for candidate filtering
        ``loopback_probes`` – list of probe dicts with ``id``, ``value``, ``description``
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.error("ssrf_probes.json not found at %s", path)
        return set(), []
    except json.JSONDecodeError as exc:
        logger.error("ssrf_probes.json parse error: %s", exc)
        return set(), []

    keyword_set: Set[str] = {
        kw.lower() for kw in data.get("url_parameter_keywords", [])
    }
    loopback_probes: List[Dict[str, Any]] = data.get("loopback_probes", [])

    logger.debug(
        "ssrf_check: loaded %d keywords, %d probes from %s",
        len(keyword_set), len(loopback_probes), path,
    )
    return keyword_set, loopback_probes
