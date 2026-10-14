"""
VortexDAST – modules/sqli_check.py
────────────────────────────────────────────────────────────────────────────
Error-Based SQL Injection Heuristic Detection Module.

Detection Strategy
------------------
1.  Load boundary probes and DBMS error-pattern regexes from
    ``payloads/sqli_probes.json``.
2.  For each discovered GET parameter and POST form field:
      a. Fetch a **baseline** response to capture the *original* response body
         and status code.  If the baseline already contains a DBMS error,
         the parameter is skipped (pre-existing 500 error — false-positive guard).
      b. Append each boundary character probe to the parameter's current value.
      c. Issue the fuzzed request.
      d. Match the response body against every compiled DBMS error regex.
      e. Diff the response status code against the baseline: a new HTTP 500
         or a matched DBMS error pattern (absent from the baseline) is
         reported as a finding.
3.  Additional Boolean-blind heuristic: compare response *length* between the
    always-true probe (``' AND '1'='1``) and the always-false probe
    (``' AND '1'='2``).  A significant length difference (>10 %) when both
    probes succeed is flagged as a potential blind SQLi indicator.

False-Positive Reduction
------------------------
*   Baseline comparison: DBMS errors already present in the original response
    are NOT counted as new findings.
*   The full matched error string is captured in the ``evidence`` field so
    analysts can quickly validate or dismiss the finding.
*   Boolean-blind findings are labelled MEDIUM (rather than HIGH) to reflect
    lower confidence without confirmed error output.

Performance
-----------
*   One baseline request is issued per parameter, not per probe.
*   DBMS patterns are compiled once at module initialisation.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Pattern, Tuple
from urllib.parse import urlencode, urlparse

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc
from core.json_fuzz import FuzzTarget, fuzz_targets_for
from core.parser import ParsedForm

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_SQLI_PROBES_PATH = os.path.join(_PAYLOADS_DIR, "sqli_probes.json")

# Minimum response-body length difference (as a fraction) to report
# Boolean-blind SQLi when no explicit error pattern is found.
_BLIND_LENGTH_THRESHOLD = 0.10  # 10 %

# Time-based blind: the measured delay must reach at least this fraction of
# the payload's own injected delay (network/app jitter margin)...
_TIME_BASED_DELAY_FRACTION = 0.6
# ...and at least this many seconds in absolute terms, so ordinary request
# jitter on a slow/CDN-fronted target can't masquerade as an injected delay.
_TIME_BASED_MIN_DELTA_SECONDS = 2.0

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 vectors for SQLi finding types
# ─────────────────────────────────────────────────────────────────────────────

# Error-based SQLi (confirmed DBMS error): network-exploitable, no privileges,
# no UI required, high C/I/A impact (full DB read/write/DoS possible).
# AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:H  → 9.8 (CRITICAL)
_CVSS_VECTOR_SQLI_ERROR = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"
)
_CVSS_SCORE_SQLI_ERROR: float = cvss_calc(_CVSS_VECTOR_SQLI_ERROR)  # 9.8

# HTTP-500 on probe (unconfirmed / probable SQLi): same attack surface but
# lower confidence — reduced C/I to Low; A still High (server crashes).
# AV:N / AC:L / PR:N / UI:N / S:U / C:L / I:L / A:H  → 7.3 (HIGH)
_CVSS_VECTOR_SQLI_500 = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="H"
)
_CVSS_SCORE_SQLI_500: float = cvss_calc(_CVSS_VECTOR_SQLI_500)  # 7.3

# Boolean-blind SQLi (heuristic / response length diff): higher complexity
# required to exploit blindly; C/I at Low; no availability impact.
# AV:N / AC:H / PR:N / UI:N / S:U / C:L / I:L / A:N  → 4.8 (MEDIUM)
_CVSS_VECTOR_SQLI_BLIND = build_vector(
    AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N"
)
_CVSS_SCORE_SQLI_BLIND: float = cvss_calc(_CVSS_VECTOR_SQLI_BLIND)  # 4.8

# Time-based blind SQLi (confirmed, reproducible timing oracle): a measured
# and re-confirmed delay is as strong a proof of query execution as an error
# signature, but the channel only yields a read oracle (no writes).
# AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:N / A:N
_CVSS_VECTOR_SQLI_TIME_BLIND = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"
)
_CVSS_SCORE_SQLI_TIME_BLIND: float = cvss_calc(_CVSS_VECTOR_SQLI_TIME_BLIND)



# ─────────────────────────────────────────────────────────────────────────────
# Internal data types
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class _CompiledPattern:
    """A single compiled DBMS error regex with its source DBMS label."""

    dbms: str
    pattern: Pattern[str]
    raw: str  # Original regex string — stored for evidence reporting.


# ─────────────────────────────────────────────────────────────────────────────
# SQLi check module
# ─────────────────────────────────────────────────────────────────────────────


class SQLiCheckModule(BaseScannerModule):
    """
    Heuristic error-based and Boolean-blind SQL Injection detection module.

    Appends benign syntax-breaking boundary characters to discovered parameters
    and monitors for DBMS-specific error signatures in the HTTP response.

    Inherits from :class:`~modules.base.BaseScannerModule`.
    """

    name: str = "sqli_check"
    description: str = (
        "Fuzzes GET and POST parameters with SQL boundary characters and "
        "matches responses against DBMS error pattern signatures. Also "
        "performs Boolean-blind length-diff heuristics."
    )

    def __init__(self, requester: Any, payloads_path: Optional[str] = None) -> None:
        """
        Parameters
        ----------
        requester : Requester
            Shared HTTP session.
        payloads_path : str | None
            Override path to ``sqli_probes.json``.
        """
        super().__init__(requester)
        path = payloads_path or _SQLI_PROBES_PATH
        (
            self._boundary_probes,
            self._time_based_probes,
            self._compiled_patterns,
            self._baseline_error_indicators,
        ) = _load_sqli_probes(path)

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        """
        Fuzz all injection vectors on the endpoint with SQLi probes.

        Parameters
        ----------
        endpoint : CrawledEndpoint
            Crawled page with its URL query parameters and forms.

        Returns
        -------
        list[Finding]
            One finding per confirmed or suspected injection vector.
        """
        findings: List[Finding] = []

        if not self._boundary_probes:
            logger.warning("sqli_check: no probes loaded — skipping %s", endpoint.url)
            return findings

        # ── GET parameters ────────────────────────────────────────────────
        if endpoint.query_params:
            findings.extend(
                self._fuzz_get_params(endpoint.url, endpoint.query_params)
            )

        # ── Linked pages with query parameters ───────────────────────────
        for link in endpoint.links:
            if link.query_params:
                findings.extend(
                    self._fuzz_get_params(link.url, link.query_params)
                )

        # ── POST forms ────────────────────────────────────────────────────
        for form in endpoint.forms:
            findings.extend(self._fuzz_form(form))

        # ── Captured JSON API requests (body leaves + REST path segments) ─
        if endpoint.json_requests:
            findings.extend(self._fuzz_json_requests(endpoint))

        return findings

    # ── GET parameter fuzzing ─────────────────────────────────────────────────

    def _fuzz_get_params(
        self,
        url: str,
        params: Dict[str, List[str]],
    ) -> List[Finding]:
        """Inject boundary probes into each GET query parameter."""
        findings: List[Finding] = []
        base_params = {k: v[0] for k, v in params.items() if v}

        for target_param, original_values in params.items():
            original_value = original_values[0] if original_values else ""

            # ── Baseline ──────────────────────────────────────────────────
            baseline_response, baseline_body, baseline_status = self._fetch_baseline(
                url, base_params
            )
            if baseline_response is None:
                continue
            if self._baseline_has_errors(baseline_body):
                logger.debug(
                    "sqli: baseline already contains DB errors at %s param=%s — skipping",
                    url, target_param,
                )
                continue

            # ── Probe injection ───────────────────────────────────────────
            for probe in self._boundary_probes:
                fuzzed_params = dict(base_params)
                # Append the boundary probe to the original parameter value.
                fuzzed_params[target_param] = original_value + probe["value"]

                parsed = urlparse(url)
                fuzzed_url = parsed._replace(query=urlencode(fuzzed_params)).geturl()

                response, error = self.requester.get(fuzzed_url)
                if error or response is None:
                    logger.debug(
                        "sqli GET request failed %s param=%s: %s",
                        fuzzed_url, target_param, error,
                    )
                    continue

                finding = self._analyse_response(
                    fuzzed_body=response.text,
                    fuzzed_status=response.status_code,
                    baseline_body=baseline_body,
                    baseline_status=baseline_status,
                    probe=probe,
                    url=fuzzed_url,
                    parameter=target_param,
                    method="GET",
                )
                if finding:
                    findings.append(finding)

            # ── Boolean-blind heuristic (GET) ─────────────────────────────
            blind_finding = self._boolean_blind_check(
                url=url,
                base_params=base_params,
                target_param=target_param,
                original_value=original_value,
                method="GET",
            )
            if blind_finding:
                findings.append(blind_finding)

            # ── Time-based blind heuristic (GET) ──────────────────────────
            time_finding = self._time_based_blind_check(
                url=url,
                base_params=base_params,
                target_param=target_param,
                original_value=original_value,
                baseline_elapsed=baseline_response.elapsed.total_seconds(),
            )
            if time_finding:
                findings.append(time_finding)

        return findings

    # ── POST form fuzzing ─────────────────────────────────────────────────────

    def _fuzz_form(self, form: ParsedForm) -> List[Finding]:
        """Inject boundary probes into each POST form field."""
        if not form.fields:
            return []

        findings: List[Finding] = []
        base_body: Dict[str, str] = {f.name: f.default_value for f in form.fields}

        for target_field in form.fields:
            original_value = target_field.default_value

            # ── Baseline ──────────────────────────────────────────────────
            baseline_response, baseline_body, baseline_status = self._post_baseline(
                form.action_url, base_body
            )
            if baseline_response is None:
                continue
            if self._baseline_has_errors(baseline_body):
                logger.debug(
                    "sqli: baseline already contains DB errors at %s field=%s — skipping",
                    form.action_url, target_field.name,
                )
                continue

            # ── Probe injection ───────────────────────────────────────────
            for probe in self._boundary_probes:
                fuzzed_body = dict(base_body)
                fuzzed_body[target_field.name] = original_value + probe["value"]

                response, error = self.requester.post(form.action_url, data=fuzzed_body)
                if error or response is None:
                    logger.debug(
                        "sqli POST failed %s field=%s: %s",
                        form.action_url, target_field.name, error,
                    )
                    continue

                finding = self._analyse_response(
                    fuzzed_body=response.text,
                    fuzzed_status=response.status_code,
                    baseline_body=baseline_body,
                    baseline_status=baseline_status,
                    probe=probe,
                    url=form.action_url,
                    parameter=target_field.name,
                    method="POST",
                )
                if finding:
                    findings.append(finding)

            # ── Boolean-blind heuristic (POST) ────────────────────────────
            blind_finding = self._boolean_blind_post_check(
                url=form.action_url,
                base_body=base_body,
                target_field=target_field.name,
                original_value=original_value,
            )
            if blind_finding:
                findings.append(blind_finding)

            # ── Time-based blind heuristic (POST) ─────────────────────────
            time_finding = self._time_based_blind_post_check(
                url=form.action_url,
                base_body=base_body,
                target_field=target_field.name,
                original_value=original_value,
                baseline_elapsed=baseline_response.elapsed.total_seconds(),
            )
            if time_finding:
                findings.append(time_finding)

        return findings

    # ── Captured JSON API request fuzzing ─────────────────────────────────────

    def _fuzz_json_requests(self, endpoint: CrawledEndpoint) -> List[Finding]:
        """
        Inject boundary probes into every scalar leaf of each captured JSON
        request's body, and into any REST-style path segment in its URL —
        the same error-based/boolean-blind/time-based-blind analysis
        already used for GET params and POST form fields, just reusing
        ``core.json_fuzz``'s leaf/path-segment targets instead.
        """
        findings: List[Finding] = []

        for captured in endpoint.json_requests:
            baseline_response, baseline_body, baseline_status = self._post_json_baseline(
                captured.url, captured.body
            )
            if baseline_response is None:
                continue
            if self._baseline_has_errors(baseline_body):
                logger.debug(
                    "sqli: JSON baseline already contains DB errors at %s — skipping",
                    captured.url,
                )
                continue

            for target in fuzz_targets_for(captured):
                for probe in self._boundary_probes:
                    fuzzed_url, fuzzed_json = target.build(probe["value"])
                    response, error = self.requester.post(fuzzed_url, json=fuzzed_json)
                    if error or response is None:
                        continue

                    finding = self._analyse_response(
                        fuzzed_body=response.text,
                        fuzzed_status=response.status_code,
                        baseline_body=baseline_body,
                        baseline_status=baseline_status,
                        probe=probe,
                        url=fuzzed_url,
                        parameter=target.label,
                        method="POST (JSON)",
                    )
                    if finding:
                        findings.append(finding)

                # Boolean/time-based blind both just extend target.original
                # with a true/false (or delay) SQL condition via
                # target.build() — that works identically for a JSON body
                # leaf and a REST path segment (e.g. the "42" in
                # "/users/42"), so both kinds get the same coverage here.
                blind_finding = self._boolean_blind_json_check(target, baseline_body)
                if blind_finding:
                    findings.append(blind_finding)

                time_finding = self._time_based_blind_json_check(
                    target, baseline_response.elapsed.total_seconds()
                )
                if time_finding:
                    findings.append(time_finding)

        return findings

    def _boolean_blind_json_check(
        self, target: FuzzTarget, baseline_body: str
    ) -> Optional[Finding]:
        """Always-true vs always-false Boolean probe pair against one JSON leaf."""
        true_probe = next(
            (p for p in self._boundary_probes if p.get("id") == "sqli_boolean_and_1eq1"), None
        )
        false_probe = next(
            (p for p in self._boundary_probes if p.get("id") == "sqli_boolean_and_1eq2"), None
        )
        if not true_probe or not false_probe:
            return None

        true_url, true_json = target.build(true_probe["value"])
        false_url, false_json = target.build(false_probe["value"])
        true_resp, err1 = self.requester.post(true_url, json=true_json)
        false_resp, err2 = self.requester.post(false_url, json=false_json)
        if err1 or err2 or true_resp is None or false_resp is None:
            return None

        return self._evaluate_boolean_diff(
            true_body=true_resp.text,
            false_body=false_resp.text,
            url=true_url,
            parameter=target.label,
            method="POST (JSON)",
        )

    def _time_based_blind_json_check(
        self, target: FuzzTarget, baseline_elapsed: float
    ) -> Optional[Finding]:
        """Try each time-based probe against one JSON leaf until one reproduces its delay."""
        for probe in self._time_based_probes:
            fuzzed_url, fuzzed_json = target.build(probe["value"])
            response, error = self.requester.post(fuzzed_url, json=fuzzed_json)
            if error or response is None:
                continue
            elapsed = response.elapsed.total_seconds()

            confirm_elapsed: Optional[float] = None
            if self._exceeds_delay_threshold(elapsed, baseline_elapsed, probe):
                confirm_response, confirm_error = self.requester.post(fuzzed_url, json=fuzzed_json)
                if confirm_error or confirm_response is None:
                    continue
                confirm_elapsed = confirm_response.elapsed.total_seconds()

            finding = self._evaluate_time_delay(
                elapsed, confirm_elapsed, baseline_elapsed, probe,
                fuzzed_url, target.label, "POST (JSON)",
            )
            if finding:
                return finding
        return None

    # ── Core response analyser ────────────────────────────────────────────────

    def _analyse_response(
        self,
        fuzzed_body: str,
        fuzzed_status: int,
        baseline_body: str,
        baseline_status: int,
        probe: Dict[str, Any],
        url: str,
        parameter: str,
        method: str,
    ) -> Optional[Finding]:
        """
        Compare the fuzzed response against the baseline and DBMS patterns.

        Returns a :class:`Finding` when:
          *  A new DBMS error pattern is matched (not present in baseline), OR
          *  The HTTP status code changed from non-500 to 500.

        Returns ``None`` otherwise.
        """
        # ── DBMS error pattern matching ───────────────────────────────────
        matched_pattern, matched_dbms, matched_snippet = self._match_dbms_errors(
            fuzzed_body
        )

        if matched_pattern:
            # Confirm the error is NOT already present in the baseline.
            baseline_match, _, _ = self._match_dbms_errors(baseline_body)
            if baseline_match:
                # Pre-existing error — not a new finding.
                return None

            logger.info(
                "⚡ SQLi ERROR: %s | param=%s | dbms=%s | pattern=%s",
                url, parameter, matched_dbms, matched_pattern.raw,
            )

            return Finding(
                title=f"SQL Injection — {matched_dbms} Error Signature Detected",
                severity=Severity.HIGH,
                confidence=Confidence.FIRM,
                url=url,
                parameter=parameter,
                payload=probe["value"],
                evidence=matched_snippet,
                description=(
                    f"Injecting the boundary probe '{probe['value']}' into parameter "
                    f"'{parameter}' via {method} triggered a {matched_dbms} database "
                    f"error in the HTTP response. The matched error pattern is: "
                    f"'{matched_pattern.raw}'.\n\n"
                    "This strongly indicates that user-supplied input is being "
                    "concatenated directly into a SQL query without parameterisation."
                ),
                remediation=(
                    "Use parameterised queries (prepared statements) for ALL database "
                    "interactions. Never concatenate user input into SQL strings. "
                    "Additionally, disable verbose database error messages in production "
                    "to prevent information leakage."
                ),
                cvss_vector=_CVSS_VECTOR_SQLI_ERROR,
                cvss_score=_CVSS_SCORE_SQLI_ERROR,
                extra={
                    "dbms": matched_dbms,
                    "matched_pattern": matched_pattern.raw,
                    "probe_id": probe.get("id"),
                    "method": method,
                    "module": self.name,
                },
            )

        # ── HTTP status code change to 500 ────────────────────────────────
        if fuzzed_status == 500 and baseline_status != 500:
            logger.info(
                "⚡ SQLi 500: %s | param=%s | probe=%s",
                url, parameter, probe["value"],
            )
            return Finding(
                title="Potential SQL Injection — Unexpected HTTP 500 on Probe Injection",
                severity=Severity.MEDIUM,
                confidence=Confidence.TENTATIVE,
                url=url,
                parameter=parameter,
                payload=probe["value"],
                evidence=f"HTTP {fuzzed_status} returned (baseline was HTTP {baseline_status})",
                description=(
                    f"Injecting '{probe['value']}' into '{parameter}' via {method} "
                    f"caused the server to return HTTP 500. The baseline request returned "
                    f"HTTP {baseline_status}. While no DBMS error string was matched, an "
                    "unhandled exception triggered by a boundary character is a strong "
                    "indicator of SQL injection vulnerability."
                ),
                remediation=(
                    "Investigate why the boundary character causes a server error. "
                    "Use parameterised queries and implement proper exception handling "
                    "that does not propagate raw database errors to HTTP responses."
                ),
                cvss_vector=_CVSS_VECTOR_SQLI_500,
                cvss_score=_CVSS_SCORE_SQLI_500,
                extra={
                    "fuzzed_status": fuzzed_status,
                    "baseline_status": baseline_status,
                    "probe_id": probe.get("id"),
                    "method": method,
                    "module": self.name,
                },
            )

        return None

    # ── Boolean-blind heuristics ──────────────────────────────────────────────

    def _boolean_blind_check(
        self,
        url: str,
        base_params: Dict[str, str],
        target_param: str,
        original_value: str,
        method: str,
    ) -> Optional[Finding]:
        """
        Compare responses for always-true vs always-false Boolean probe pair (GET).

        A significant length difference between the two responses when no
        explicit error occurred suggests Boolean-based blind SQL injection.
        """
        true_probe = next(
            (p for p in self._boundary_probes if p.get("id") == "sqli_boolean_and_1eq1"), None
        )
        false_probe = next(
            (p for p in self._boundary_probes if p.get("id") == "sqli_boolean_and_1eq2"), None
        )
        if not true_probe or not false_probe:
            return None

        true_params = dict(base_params)
        true_params[target_param] = original_value + true_probe["value"]
        false_params = dict(base_params)
        false_params[target_param] = original_value + false_probe["value"]

        parsed = urlparse(url)
        true_url = parsed._replace(query=urlencode(true_params)).geturl()
        false_url = parsed._replace(query=urlencode(false_params)).geturl()

        true_resp, err1 = self.requester.get(true_url)
        false_resp, err2 = self.requester.get(false_url)

        if err1 or err2 or true_resp is None or false_resp is None:
            return None

        return self._evaluate_boolean_diff(
            true_body=true_resp.text,
            false_body=false_resp.text,
            url=url,
            parameter=target_param,
            method=method,
        )

    def _boolean_blind_post_check(
        self,
        url: str,
        base_body: Dict[str, str],
        target_field: str,
        original_value: str,
    ) -> Optional[Finding]:
        """
        Compare responses for always-true vs always-false Boolean probe pair (POST).
        """
        true_probe = next(
            (p for p in self._boundary_probes if p.get("id") == "sqli_boolean_and_1eq1"), None
        )
        false_probe = next(
            (p for p in self._boundary_probes if p.get("id") == "sqli_boolean_and_1eq2"), None
        )
        if not true_probe or not false_probe:
            return None

        true_body = dict(base_body)
        true_body[target_field] = original_value + true_probe["value"]
        false_body = dict(base_body)
        false_body[target_field] = original_value + false_probe["value"]

        true_resp, err1 = self.requester.post(url, data=true_body)
        false_resp, err2 = self.requester.post(url, data=false_body)

        if err1 or err2 or true_resp is None or false_resp is None:
            return None

        return self._evaluate_boolean_diff(
            true_body=true_resp.text,
            false_body=false_resp.text,
            url=url,
            parameter=target_field,
            method="POST",
        )

    def _evaluate_boolean_diff(
        self,
        true_body: str,
        false_body: str,
        url: str,
        parameter: str,
        method: str,
    ) -> Optional[Finding]:
        """
        Emit a MEDIUM-severity Boolean-blind SQLi finding when response
        lengths differ by more than ``_BLIND_LENGTH_THRESHOLD``.
        """
        len_true = len(true_body)
        len_false = len(false_body)

        if len_true == 0 or len_false == 0:
            return None

        diff_ratio = abs(len_true - len_false) / max(len_true, len_false)
        if diff_ratio < _BLIND_LENGTH_THRESHOLD:
            return None

        logger.info(
            "⚡ SQLi BLIND: %s | param=%s | len_diff=%.1f%%",
            url, parameter, diff_ratio * 100,
        )

        return Finding(
            title="Potential Boolean-Blind SQL Injection — Response Length Differential",
            severity=Severity.MEDIUM,
                confidence=Confidence.TENTATIVE,
            url=url,
            parameter=parameter,
            payload="' AND '1'='1 vs ' AND '1'='2",
            evidence=(
                f"Always-true response: {len_true} bytes | "
                f"Always-false response: {len_false} bytes | "
                f"Difference: {diff_ratio * 100:.1f}%"
            ),
            description=(
                f"The response body length differed by {diff_ratio * 100:.1f}% between "
                "an always-true SQL condition and an always-false condition injected into "
                f"parameter '{parameter}' via {method}. No DBMS error string was detected, "
                "but the significant length difference is consistent with Boolean-based "
                "blind SQL injection."
            ),
            remediation=(
                "Use parameterised queries. If the application intentionally behaves "
                "differently on different inputs, verify that user data is not embedded "
                "in SQL logic without sanitisation."
            ),
            cvss_vector=_CVSS_VECTOR_SQLI_BLIND,
            cvss_score=_CVSS_SCORE_SQLI_BLIND,
            extra={
                "len_true_probe": len_true,
                "len_false_probe": len_false,
                "diff_ratio": round(diff_ratio, 4),
                "method": method,
                "module": self.name,
            },
        )

    # ── Time-based blind heuristics ───────────────────────────────────────────

    def _time_based_blind_check(
        self,
        url: str,
        base_params: Dict[str, str],
        target_param: str,
        original_value: str,
        baseline_elapsed: float,
    ) -> Optional[Finding]:
        """Try each time-based probe (GET) until one reproduces its delay."""
        for probe in self._time_based_probes:
            fuzzed_params = dict(base_params)
            fuzzed_params[target_param] = original_value + probe["value"]
            parsed = urlparse(url)
            fuzzed_url = parsed._replace(query=urlencode(fuzzed_params)).geturl()

            response, error = self.requester.get(fuzzed_url)
            if error or response is None:
                continue
            elapsed = response.elapsed.total_seconds()

            confirm_elapsed: Optional[float] = None
            if self._exceeds_delay_threshold(elapsed, baseline_elapsed, probe):
                confirm_response, confirm_error = self.requester.get(fuzzed_url)
                if confirm_error or confirm_response is None:
                    continue
                confirm_elapsed = confirm_response.elapsed.total_seconds()

            finding = self._evaluate_time_delay(
                elapsed, confirm_elapsed, baseline_elapsed, probe,
                url, target_param, "GET",
            )
            if finding:
                return finding
        return None

    def _time_based_blind_post_check(
        self,
        url: str,
        base_body: Dict[str, str],
        target_field: str,
        original_value: str,
        baseline_elapsed: float,
    ) -> Optional[Finding]:
        """Try each time-based probe (POST) until one reproduces its delay."""
        for probe in self._time_based_probes:
            fuzzed_body = dict(base_body)
            fuzzed_body[target_field] = original_value + probe["value"]

            response, error = self.requester.post(url, data=fuzzed_body)
            if error or response is None:
                continue
            elapsed = response.elapsed.total_seconds()

            confirm_elapsed: Optional[float] = None
            if self._exceeds_delay_threshold(elapsed, baseline_elapsed, probe):
                confirm_response, confirm_error = self.requester.post(url, data=fuzzed_body)
                if confirm_error or confirm_response is None:
                    continue
                confirm_elapsed = confirm_response.elapsed.total_seconds()

            finding = self._evaluate_time_delay(
                elapsed, confirm_elapsed, baseline_elapsed, probe,
                url, target_field, "POST",
            )
            if finding:
                return finding
        return None

    @staticmethod
    def _exceeds_delay_threshold(
        elapsed: float, baseline_elapsed: float, probe: Dict[str, Any]
    ) -> bool:
        delay = probe.get("delay_seconds", 0)
        threshold = max(delay * _TIME_BASED_DELAY_FRACTION, _TIME_BASED_MIN_DELTA_SECONDS)
        return (elapsed - baseline_elapsed) >= threshold

    def _evaluate_time_delay(
        self,
        elapsed: float,
        confirm_elapsed: Optional[float],
        baseline_elapsed: float,
        probe: Dict[str, Any],
        url: str,
        parameter: str,
        method: str,
    ) -> Optional[Finding]:
        """
        Emit a HIGH-confidence time-based blind SQLi finding only when the
        injected delay is reproduced on a confirmation request — a single
        slow sample is not trusted, since it may just be network jitter
        (verified in practice against CDN/WAF-fronted targets).
        """
        if not self._exceeds_delay_threshold(elapsed, baseline_elapsed, probe):
            return None
        if confirm_elapsed is None or not self._exceeds_delay_threshold(
            confirm_elapsed, baseline_elapsed, probe
        ):
            return None

        delay = probe.get("delay_seconds", 0)
        dbms = probe.get("dbms", "Unknown DBMS")
        delta = elapsed - baseline_elapsed

        logger.info(
            "⚡ SQLi TIME-BLIND: %s | param=%s | dbms=%s | delta=%.2fs (expected ~%ss)",
            url, parameter, dbms, delta, delay,
        )

        return Finding(
            title=f"Time-Based Blind SQL Injection — {dbms}",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            parameter=parameter,
            payload=probe["value"],
            evidence=(
                f"Baseline response: {baseline_elapsed:.2f}s | "
                f"injected delay probe (expected ~{delay}s): {elapsed:.2f}s | "
                f"reproduced on confirmation request: {confirm_elapsed:.2f}s"
            ),
            description=(
                f"Injecting a time-delay payload ('{probe['value']}') into parameter "
                f"'{parameter}' via {method} consistently added ~{delta:.1f}s to the "
                f"response time relative to baseline, and this delay was reproduced on "
                f"a confirmation request. This indicates the injected SQL is executed "
                f"by the database ({dbms}) even though no error or visible output is "
                "returned to the response body — a classic blind SQL injection oracle."
            ),
            remediation=(
                "Use parameterised queries (prepared statements) for ALL database "
                "interactions. Never concatenate user input into SQL strings."
            ),
            cvss_vector=_CVSS_VECTOR_SQLI_TIME_BLIND,
            cvss_score=_CVSS_SCORE_SQLI_TIME_BLIND,
            extra={
                "dbms": dbms,
                "probe_id": probe.get("id"),
                "expected_delay_s": delay,
                "measured_delta_s": round(delta, 2),
                "method": method,
                "module": self.name,
            },
        )

    # ── Private utilities ─────────────────────────────────────────────────────

    def _match_dbms_errors(
        self, body: str
    ) -> Tuple[Optional["_CompiledPattern"], str, str]:
        """
        Scan a response body for any compiled DBMS error signature.

        Returns
        -------
        (matched_pattern, dbms_name, evidence_snippet)
            All are empty/None when no match is found.
        """
        for compiled in self._compiled_patterns:
            match = compiled.pattern.search(body)
            if match:
                start = max(0, match.start() - 100)
                end = min(len(body), match.end() + 100)
                snippet = body[start:end]
                return compiled, compiled.dbms, snippet
        return None, "", ""

    def _baseline_has_errors(self, body: str) -> bool:
        """
        Return True if the baseline response already contains either a
        DBMS error pattern or a generic server-error indicator.
        """
        body_lower = body.lower()
        for indicator in self._baseline_error_indicators:
            if indicator in body_lower:
                return True
        matched, _, _ = self._match_dbms_errors(body)
        return matched is not None

    def _fetch_baseline(
        self, url: str, params: Dict[str, str]
    ) -> Tuple[Any, str, int]:
        """
        Fetch the unmodified URL with original parameters for baseline capture.

        Returns
        -------
        (response, body_text, status_code)
            response is None on failure; body is empty string.
        """
        parsed = urlparse(url)
        baseline_url = parsed._replace(query=urlencode(params)).geturl()
        response, error = self.requester.get(baseline_url)
        if error or response is None:
            logger.debug("sqli baseline fetch failed for %s: %s", baseline_url, error)
            return None, "", 0
        return response, response.text, response.status_code

    def _post_baseline(
        self, url: str, data: Dict[str, str]
    ) -> Tuple[Any, str, int]:
        """Fetch the unmodified POST form for baseline capture."""
        response, error = self.requester.post(url, data=data)
        if error or response is None:
            logger.debug("sqli POST baseline fetch failed for %s: %s", url, error)
            return None, "", 0
        return response, response.text, response.status_code

    def _post_json_baseline(self, url: str, json_data: Any) -> Tuple[Any, str, int]:
        """Fetch the unmodified captured JSON request for baseline capture."""
        response, error = self.requester.post(url, json=json_data)
        if error or response is None:
            logger.debug("sqli POST (JSON) baseline fetch failed for %s: %s", url, error)
            return None, "", 0
        return response, response.text, response.status_code


# ─────────────────────────────────────────────────────────────────────────────
# Payload loader
# ─────────────────────────────────────────────────────────────────────────────


def _load_sqli_probes(
    path: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List["_CompiledPattern"], List[str]]:
    """
    Load SQLi probe definitions and compile DBMS error regex patterns.

    Parameters
    ----------
    path : str
        Path to ``sqli_probes.json``.

    Returns
    -------
    (boundary_probes, time_based_probes, compiled_patterns, baseline_error_indicators)
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.error("sqli_probes.json not found at %s", path)
        return [], [], [], []
    except json.JSONDecodeError as exc:
        logger.error("sqli_probes.json parse error: %s", exc)
        return [], [], [], []

    boundary_probes: List[Dict[str, Any]] = data.get("boundary_probes", [])
    time_based_probes: List[Dict[str, Any]] = data.get("time_based_probes", [])

    # Compile all DBMS error regexes.
    compiled_patterns: List[_CompiledPattern] = []
    raw_patterns: Dict[str, List[str]] = (
        data.get("dbms_error_patterns", {}).get("patterns", {})
    )
    for dbms, patterns in raw_patterns.items():
        for raw_pattern in patterns:
            try:
                compiled = _CompiledPattern(
                    dbms=dbms,
                    pattern=re.compile(raw_pattern, re.IGNORECASE | re.DOTALL),
                    raw=raw_pattern,
                )
                compiled_patterns.append(compiled)
            except re.error as exc:
                logger.warning("Invalid regex for %s: '%s' — %s", dbms, raw_pattern, exc)

    baseline_indicators: List[str] = (
        data.get("false_positive_filter", {}).get("baseline_error_indicators", [])
    )

    logger.debug(
        "sqli_check: loaded %d probes, %d time-based probes, %d compiled patterns from %s",
        len(boundary_probes), len(time_based_probes), len(compiled_patterns), path,
    )
    return boundary_probes, time_based_probes, compiled_patterns, baseline_indicators
