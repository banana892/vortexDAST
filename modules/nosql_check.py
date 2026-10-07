"""
VortexDAST – modules/nosql_check.py
────────────────────────────────────────────────────────────────────────────
NoSQL Injection Heuristic Detection Module (MongoDB / CouchDB / document stores).

Detection Strategy
------------------
Two complementary signals are used, mirroring the error-based + differential
approach of :mod:`modules.sqli_check`:

1.  **Error-based** (``firm``): append benign syntax-breaking boundary strings
    to a parameter value and match the response against known NoSQL driver /
    parser error signatures (``MongoError``, ``FailedToParse``,
    ``query_parse_error``, …). A signature that is *new* relative to the
    baseline is reported.

2.  **Operator-injection differential** (``tentative``): rewrite the parameter
    *key* into an operator form (``user`` → ``user[$ne]``) and compare an
    always-true operator (``$ne`` to a random value, matching every document)
    against an always-false operator (``$eq`` to the same random value). A
    significant response-length difference indicates the operator reached the
    query engine and altered its logic — the hallmark of NoSQL query-logic
    bypass (e.g. authentication bypass).

False-Positive Reduction
------------------------
*   Baseline comparison: pre-existing NoSQL errors are not counted.
*   The always-true response must also differ from the unmodified baseline, so
    a page that simply ignores unknown parameters is not flagged.
*   Operator findings are ``tentative`` (manual verification required).

Safety
------
*   Only comparison operators (``$ne`` / ``$eq``) and malformed-syntax markers
    are sent. No ``$where`` code execution, ``$out``, map-reduce, or any
    database-mutating operator is used.
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
from core.parser import ParsedForm

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_NOSQL_PROBES_PATH = os.path.join(_PAYLOADS_DIR, "nosql_probes.json")

# Minimum response-length difference (fraction) for the operator differential.
_OPERATOR_LENGTH_THRESHOLD = 0.10  # 10 %

# Error-based NoSQLi (confirmed driver/parser error): network-exploitable, low
# complexity, no privileges/UI. Query-logic control → high confidentiality and
# integrity impact (data read / auth bypass).
# AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:N  → 9.1 (CRITICAL)
_CVSS_VECTOR_NOSQL_ERROR = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"
)
_CVSS_SCORE_NOSQL_ERROR: float = cvss_calc(_CVSS_VECTOR_NOSQL_ERROR)

# Operator-injection differential (heuristic logic bypass): higher complexity
# to exploit blindly; Low C/I; no availability impact.
# AV:N / AC:H / PR:N / UI:N / S:U / C:L / I:L / A:N  → 4.8 (MEDIUM)
_CVSS_VECTOR_NOSQL_OPERATOR = build_vector(
    AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N"
)
_CVSS_SCORE_NOSQL_OPERATOR: float = cvss_calc(_CVSS_VECTOR_NOSQL_OPERATOR)


@dataclass
class _CompiledPattern:
    """A single compiled NoSQL error regex with its source DB label."""

    db: str
    pattern: Pattern[str]
    raw: str


class NoSQLCheckModule(BaseScannerModule):
    """
    Heuristic error-based and operator-injection NoSQL Injection detection.

    Inherits from :class:`~modules.base.BaseScannerModule`.
    """

    name: str = "nosql_check"
    description: str = (
        "Injects NoSQL boundary characters and comparison operators "
        "($ne/$eq) into GET and POST parameters, matching driver error "
        "signatures and detecting query-logic bypass via response diffing."
    )

    def __init__(self, requester: Any, payloads_path: Optional[str] = None) -> None:
        super().__init__(requester)
        path = payloads_path or _NOSQL_PROBES_PATH
        (
            self._boundary_probes,
            self._operator_probes,
            self._json_operator_probes,
            self._compiled_patterns,
            self._baseline_error_indicators,
        ) = _load_nosql_probes(path)

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        findings: List[Finding] = []

        if not self._boundary_probes and not self._operator_probes and not self._json_operator_probes:
            logger.warning("nosql_check: no probes loaded — skipping %s", endpoint.url)
            return findings

        if endpoint.query_params:
            findings.extend(self._fuzz_get_params(endpoint.url, endpoint.query_params))

        for link in endpoint.links:
            link_params = getattr(link, "query_params", None)
            if link_params:
                findings.extend(self._fuzz_get_params(link.url, link_params))

        for form in endpoint.forms:
            findings.extend(self._fuzz_form(form))
            findings.extend(self._fuzz_json_body(form))

        return findings

    # ── GET fuzzing ───────────────────────────────────────────────────────────

    def _fuzz_get_params(
        self, url: str, params: Dict[str, List[str]]
    ) -> List[Finding]:
        findings: List[Finding] = []
        base_params = {k: v[0] for k, v in params.items() if v}

        for target_param, original_values in params.items():
            original_value = original_values[0] if original_values else ""

            baseline_body, baseline_status = self._get_baseline(url, base_params)
            if baseline_body is None:
                continue
            if self._baseline_has_errors(baseline_body):
                logger.debug(
                    "nosql: baseline already errors at %s param=%s — skipping",
                    url, target_param,
                )
                continue

            # (1) Error-based value injection.
            for probe in self._boundary_probes:
                fuzzed = dict(base_params)
                fuzzed[target_param] = original_value + probe["value"]
                body = self._get_body(url, fuzzed)
                if body is None:
                    continue
                finding = self._analyse_error(
                    body, baseline_body, probe, url, target_param, "GET"
                )
                if finding:
                    findings.append(finding)
                    break

            # (2) Operator-injection differential (replace the key).
            op_finding = self._operator_differential_get(
                url, base_params, target_param, baseline_body
            )
            if op_finding:
                findings.append(op_finding)

        return findings

    # ── POST fuzzing ──────────────────────────────────────────────────────────

    def _fuzz_form(self, form: ParsedForm) -> List[Finding]:
        if not form.fields:
            return []

        findings: List[Finding] = []
        base_body: Dict[str, str] = {f.name: f.default_value for f in form.fields}

        for target_field in form.fields:
            original_value = target_field.default_value

            baseline_body, _ = self._post_baseline(form.action_url, base_body)
            if baseline_body is None:
                continue
            if self._baseline_has_errors(baseline_body):
                continue

            for probe in self._boundary_probes:
                fuzzed = dict(base_body)
                fuzzed[target_field.name] = original_value + probe["value"]
                body = self._post_body(form.action_url, fuzzed)
                if body is None:
                    continue
                finding = self._analyse_error(
                    body, baseline_body, probe, form.action_url, target_field.name, "POST"
                )
                if finding:
                    findings.append(finding)
                    break

            op_finding = self._operator_differential_post(
                form.action_url, base_body, target_field.name, baseline_body
            )
            if op_finding:
                findings.append(op_finding)

        return findings

    # ── JSON body fuzzing ─────────────────────────────────────────────────────

    def _fuzz_json_body(self, form: ParsedForm) -> List[Finding]:
        if not form.fields:
            return []

        findings: List[Finding] = []
        base_body: Dict[str, Any] = {f.name: f.default_value for f in form.fields}

        baseline_body, status = self._post_json_baseline(form.action_url, base_body)
        if baseline_body is None or status in (404, 405, 415):
            return []
        if self._baseline_has_errors(baseline_body):
            return []

        for target_field in form.fields:
            original_value = target_field.default_value

            for probe in self._boundary_probes:
                fuzzed = dict(base_body)
                fuzzed[target_field.name] = original_value + probe["value"]
                body = self._post_json_body(form.action_url, fuzzed)
                if body is None:
                    continue
                finding = self._analyse_error(
                    body, baseline_body, probe, form.action_url, target_field.name, "POST (JSON)"
                )
                if finding:
                    findings.append(finding)
                    break

            op_finding = self._operator_differential_json(
                form.action_url, base_body, target_field.name, baseline_body
            )
            if op_finding:
                findings.append(op_finding)

        return findings

    def _operator_differential_json(
        self,
        url: str,
        base_body: Dict[str, Any],
        target_field: str,
        baseline_body: str,
    ) -> Optional[Finding]:
        true_probe, false_probe = self._json_operator_pair()
        if not true_probe or not false_probe:
            return None

        true_data = dict(base_body)
        true_data[target_field] = {true_probe["operator"]: true_probe["value"]}
        false_data = dict(base_body)
        false_data[target_field] = {false_probe["operator"]: false_probe["value"]}

        true_body = self._post_json_body(url, true_data)
        false_body = self._post_json_body(url, false_data)
        if true_body is None or false_body is None:
            return None

        return self._evaluate_operator_diff(
            true_body, false_body, baseline_body, url, target_field, "POST (JSON)"
        )

    # ── Error analysis ────────────────────────────────────────────────────────

    def _analyse_error(
        self,
        body: str,
        baseline_body: str,
        probe: Dict[str, Any],
        url: str,
        parameter: str,
        method: str,
    ) -> Optional[Finding]:
        matched, db, snippet = self._match_errors(body)
        if not matched:
            return None
        # Confirm the error is new relative to the baseline.
        baseline_match, _, _ = self._match_errors(baseline_body)
        if baseline_match:
            return None

        logger.info(
            "⚡ NoSQLi ERROR: %s | param=%s | db=%s | pattern=%s",
            url, parameter, db, matched.raw,
        )
        return Finding(
            title=f"NoSQL Injection — {db} Error Signature Detected",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            parameter=parameter,
            payload=probe["value"],
            evidence=snippet,
            description=(
                f"Injecting the boundary probe '{probe['value']}' into parameter "
                f"'{parameter}' via {method} triggered a {db} error in the response "
                f"(matched pattern: '{matched.raw}'). This indicates user input is "
                "passed into a NoSQL query without proper sanitisation or type "
                "enforcement."
            ),
            remediation=(
                "Validate and type-cast all user input before using it in NoSQL "
                "queries (reject objects where a string is expected). Use an ODM "
                "with strict schemas, disable operator parsing on query strings "
                "(e.g. mongo-sanitize / express-mongo-sanitize), and suppress "
                "verbose driver errors in production."
            ),
            cvss_vector=_CVSS_VECTOR_NOSQL_ERROR,
            cvss_score=_CVSS_SCORE_NOSQL_ERROR,
            extra={
                "db": db,
                "matched_pattern": matched.raw,
                "probe_id": probe.get("id"),
                "method": method,
                "module": self.name,
            },
        )

    # ── Operator differential ─────────────────────────────────────────────────

    def _operator_differential_get(
        self,
        url: str,
        base_params: Dict[str, str],
        target_param: str,
        baseline_body: str,
    ) -> Optional[Finding]:
        true_probe, false_probe = self._operator_pair()
        if not true_probe or not false_probe:
            return None

        true_params = {k: v for k, v in base_params.items() if k != target_param}
        true_params[f"{target_param}[{true_probe['operator']}]"] = true_probe["value"]
        false_params = {k: v for k, v in base_params.items() if k != target_param}
        false_params[f"{target_param}[{false_probe['operator']}]"] = false_probe["value"]

        true_body = self._get_body(url, true_params)
        false_body = self._get_body(url, false_params)
        if true_body is None or false_body is None:
            return None

        return self._evaluate_operator_diff(
            true_body, false_body, baseline_body, url, target_param, "GET"
        )

    def _operator_differential_post(
        self,
        url: str,
        base_body: Dict[str, str],
        target_field: str,
        baseline_body: str,
    ) -> Optional[Finding]:
        true_probe, false_probe = self._operator_pair()
        if not true_probe or not false_probe:
            return None

        true_data = {k: v for k, v in base_body.items() if k != target_field}
        true_data[f"{target_field}[{true_probe['operator']}]"] = true_probe["value"]
        false_data = {k: v for k, v in base_body.items() if k != target_field}
        false_data[f"{target_field}[{false_probe['operator']}]"] = false_probe["value"]

        true_body = self._post_body(url, true_data)
        false_body = self._post_body(url, false_data)
        if true_body is None or false_body is None:
            return None

        return self._evaluate_operator_diff(
            true_body, false_body, baseline_body, url, target_field, "POST"
        )

    def _evaluate_operator_diff(
        self,
        true_body: str,
        false_body: str,
        baseline_body: str,
        url: str,
        parameter: str,
        method: str,
    ) -> Optional[Finding]:
        len_true, len_false = len(true_body), len(false_body)
        if len_true == 0 or len_false == 0:
            return None

        diff_ratio = abs(len_true - len_false) / max(len_true, len_false)
        if diff_ratio < _OPERATOR_LENGTH_THRESHOLD:
            return None

        # Guard: the always-true response must also differ from the unmodified
        # baseline, otherwise the app likely ignores the injected operator key.
        if true_body == baseline_body:
            return None

        logger.info(
            "⚡ NoSQLi OPERATOR: %s | param=%s | len_diff=%.1f%%",
            url, parameter, diff_ratio * 100,
        )
        return Finding(
            title="Potential NoSQL Injection — Operator Query-Logic Bypass",
            severity=Severity.MEDIUM,
            confidence=Confidence.TENTATIVE,
            url=url,
            parameter=parameter,
            payload=f"{parameter}[$ne] vs {parameter}[$eq]",
            evidence=(
                f"Always-true ($ne) response: {len_true} bytes | "
                f"always-false ($eq) response: {len_false} bytes | "
                f"difference: {diff_ratio * 100:.1f}%"
            ),
            description=(
                f"Rewriting parameter '{parameter}' into operator form via {method} "
                f"produced a {diff_ratio * 100:.1f}% response-length difference between "
                "an always-true ($ne) and always-false ($eq) comparison operator. This "
                "indicates the operator reached the query engine and changed its result "
                "set — consistent with NoSQL query-logic bypass (e.g. authentication "
                "bypass)."
            ),
            remediation=(
                "Reject non-string input where strings are expected and strip MongoDB "
                "operators from request parameters (express-mongo-sanitize or "
                "equivalent). Enforce strict schema validation on all query inputs."
            ),
            cvss_vector=_CVSS_VECTOR_NOSQL_OPERATOR,
            cvss_score=_CVSS_SCORE_NOSQL_OPERATOR,
            extra={
                "len_true_probe": len_true,
                "len_false_probe": len_false,
                "diff_ratio": round(diff_ratio, 4),
                "method": method,
                "module": self.name,
            },
        )

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _operator_pair(self) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        true_probe = next(
            (p for p in self._operator_probes if p.get("logic") == "true"), None
        )
        false_probe = next(
            (p for p in self._operator_probes if p.get("logic") == "false"), None
        )
        return true_probe, false_probe

    def _json_operator_pair(self) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        true_probe = next(
            (p for p in self._json_operator_probes if p.get("logic") == "true"), None
        )
        false_probe = next(
            (p for p in self._json_operator_probes if p.get("logic") == "false"), None
        )
        if not true_probe or not false_probe:
            return self._operator_pair()
        return true_probe, false_probe

    def _match_errors(self, body: str) -> Tuple[Optional[_CompiledPattern], str, str]:
        for compiled in self._compiled_patterns:
            match = compiled.pattern.search(body)
            if match:
                start = max(0, match.start() - 100)
                end = min(len(body), match.end() + 100)
                return compiled, compiled.db, body[start:end]
        return None, "", ""

    def _baseline_has_errors(self, body: str) -> bool:
        body_lower = body.lower()
        for indicator in self._baseline_error_indicators:
            if indicator in body_lower:
                return True
        matched, _, _ = self._match_errors(body)
        return matched is not None

    def _get_baseline(
        self, url: str, params: Dict[str, str]
    ) -> Tuple[Optional[str], int]:
        parsed = urlparse(url)
        baseline_url = parsed._replace(query=urlencode(params)).geturl()
        try:
            res = self.requester.get(baseline_url)
            if not isinstance(res, tuple) or len(res) != 2:
                return None, 0
            response, error = res
        except Exception:
            return None, 0
        if error or response is None:
            logger.debug("nosql GET baseline failed for %s: %s", baseline_url, error)
            return None, 0
        return getattr(response, "text", ""), getattr(response, "status_code", 0)

    def _get_body(self, url: str, params: Dict[str, str]) -> Optional[str]:
        parsed = urlparse(url)
        fuzzed_url = parsed._replace(query=urlencode(params)).geturl()
        try:
            res = self.requester.get(fuzzed_url)
            if not isinstance(res, tuple) or len(res) != 2:
                return None
            response, error = res
        except Exception:
            return None
        if error or response is None:
            logger.debug("nosql GET failed for %s: %s", fuzzed_url, error)
            return None
        return getattr(response, "text", "")

    def _post_baseline(
        self, url: str, data: Dict[str, str]
    ) -> Tuple[Optional[str], int]:
        try:
            res = self.requester.post(url, data=data)
            if not isinstance(res, tuple) or len(res) != 2:
                return None, 0
            response, error = res
        except Exception:
            return None, 0
        if error or response is None:
            logger.debug("nosql POST baseline failed for %s: %s", url, error)
            return None, 0
        return getattr(response, "text", ""), getattr(response, "status_code", 0)

    def _post_body(self, url: str, data: Dict[str, str]) -> Optional[str]:
        try:
            res = self.requester.post(url, data=data)
            if not isinstance(res, tuple) or len(res) != 2:
                return None
            response, error = res
        except Exception:
            return None
        if error or response is None:
            logger.debug("nosql POST failed for %s: %s", url, error)
            return None
        return getattr(response, "text", "")

    def _post_json_baseline(
        self, url: str, json_data: Dict[str, Any]
    ) -> Tuple[Optional[str], int]:
        try:
            res = self.requester.post(url, json=json_data)
            if not isinstance(res, tuple) or len(res) != 2:
                return None, 0
            response, error = res
        except Exception:
            return None, 0
        if error or response is None:
            logger.debug("nosql POST (JSON) baseline failed for %s: %s", url, error)
            return None, 0
        return getattr(response, "text", ""), getattr(response, "status_code", 0)

    def _post_json_body(self, url: str, json_data: Dict[str, Any]) -> Optional[str]:
        try:
            res = self.requester.post(url, json=json_data)
            if not isinstance(res, tuple) or len(res) != 2:
                return None
            response, error = res
        except Exception:
            return None
        if error or response is None:
            logger.debug("nosql POST (JSON) failed for %s: %s", url, error)
            return None
        return getattr(response, "text", "")


# ─────────────────────────────────────────────────────────────────────────────
# Payload loader
# ─────────────────────────────────────────────────────────────────────────────


def _load_nosql_probes(
    path: str,
) -> Tuple[
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[_CompiledPattern],
    List[str],
]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.error("nosql_probes.json not found at %s", path)
        return [], [], [], [], []
    except json.JSONDecodeError as exc:
        logger.error("nosql_probes.json parse error: %s", exc)
        return [], [], [], [], []

    boundary_probes: List[Dict[str, Any]] = data.get("boundary_probes", [])
    operator_probes: List[Dict[str, Any]] = data.get("operator_probes", [])
    json_operator_probes: List[Dict[str, Any]] = data.get(
        "json_operator_probes", operator_probes
    )

    compiled_patterns: List[_CompiledPattern] = []
    raw_patterns: Dict[str, List[str]] = (
        data.get("nosql_error_patterns", {}).get("patterns", {})
    )
    for db, patterns in raw_patterns.items():
        for raw_pattern in patterns:
            try:
                compiled_patterns.append(
                    _CompiledPattern(
                        db=db,
                        pattern=re.compile(raw_pattern, re.IGNORECASE | re.DOTALL),
                        raw=raw_pattern,
                    )
                )
            except re.error as exc:
                logger.warning("Invalid NoSQL regex for %s: '%s' — %s", db, raw_pattern, exc)

    baseline_indicators: List[str] = (
        data.get("false_positive_filter", {}).get("baseline_error_indicators", [])
    )

    logger.debug(
        "nosql_check: loaded %d boundary, %d operator, %d JSON probes, %d patterns from %s",
        len(boundary_probes),
        len(operator_probes),
        len(json_operator_probes),
        len(compiled_patterns),
        path,
    )
    return (
        boundary_probes,
        operator_probes,
        json_operator_probes,
        compiled_patterns,
        baseline_indicators,
    )
