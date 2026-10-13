"""
VortexDAST – modules/traversal_check.py
────────────────────────────────────────────────────────────────────────────
Path Traversal / Local File Inclusion (LFI) Detection Module.

Detection Strategy
------------------
1. Load traversal probe sequences and OS-artifact detection regexes from
   ``payloads/traversal_probes.json`` at class initialisation.  Regex
   patterns are compiled once at load time for performance.

2. **Candidate parameter identification** — collect every URL query parameter
   from the endpoint URL, plus every GET-method form field (added to the
   same GET candidate set). Every POST-method form's own fields are
   candidates too, fuzzed via POST against that form's own baseline — this
   is the module's own "GET-only" follow-up from the roadmap (§5 item 6);
   it previously discarded every POST form's fields entirely.

3. **Baseline fetch** — one baseline per request shape: a single GET of the
   endpoint URL covers every GET candidate, and each POST form gets its own
   baseline POST (its own fields, unmodified) before any of *its* fields are
   fuzzed. Each baseline records response body text and HTTP status code.

   If a baseline body already matches any detection pattern, that baseline's
   candidates are skipped entirely (eliminates pre-existing false positives
   on error pages that coincidentally contain UNIX-like text).

4. **Probe injection** — for each candidate parameter × each probe:
   a. Substitute the parameter/field value with the probe sequence.
   b. Issue a GET (query parameter) or POST (form field) request with the
      modified value — whichever request shape the candidate came from.
   c. Inspect the response body against all compiled detection patterns.

5. **Confirmation** — a finding is emitted when:
   - Response status < 500 (avoids generic server errors).
   - At least one detection pattern matches the response body.
   - The same pattern did NOT match the baseline body.

6. **Deduplication** — once a confirmed finding is recorded for a
   ``(url, parameter_name)`` pair, that pair is not probed further with
   additional payloads (first confirmed hit is sufficient).

Severity
--------
* HIGH  (CVSS 7.5) — detection pattern matched; OS file content confirmed.
* MEDIUM (CVSS 5.3) — status code anomaly (unexpected 200 on normally
  non-200 endpoint) without a matching body pattern.

False-Positive Suppression
--------------------------
*   Baseline body comparison eliminates pre-existing pattern matches.
*   Status ≥ 500 responses are skipped (generic server errors).
*   Each ``(url, param_name)`` pair is reported at most once.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc
from core.parser import ParsedForm
from core.requester import Requester

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_TRAVERSAL_PROBES_PATH = os.path.join(_PAYLOADS_DIR, "traversal_probes.json")

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 vectors
# ─────────────────────────────────────────────────────────────────────────────

# HIGH — body pattern matched; OS file content confirmed in response.
# AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:N / A:N  → 7.5
_CVSS_VECTOR_HIGH = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"
)
_CVSS_SCORE_HIGH: float = cvss_calc(_CVSS_VECTOR_HIGH)  # 7.5

# MEDIUM — status anomaly without confirmed body content.
# AV:N / AC:H / PR:N / UI:N / S:U / C:L / I:N / A:N  → 3.7
_CVSS_VECTOR_MEDIUM = build_vector(
    AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"
)
_CVSS_SCORE_MEDIUM: float = cvss_calc(_CVSS_VECTOR_MEDIUM)  # 3.7


# ─────────────────────────────────────────────────────────────────────────────
# Compiled detection pattern type
# ─────────────────────────────────────────────────────────────────────────────


class _DetectionPattern:
    """Pre-compiled regex for LFI response body matching."""

    __slots__ = ("id", "os", "description", "regex")

    def __init__(self, raw: Dict) -> None:
        self.id: str = raw["id"]
        self.os: str = raw.get("os", "any")
        self.description: str = raw.get("description", "")
        self.regex: re.Pattern[str] = re.compile(raw["pattern"], re.MULTILINE)

    def matches(self, text: str) -> bool:
        """Return ``True`` if the pattern matches anywhere in ``text``."""
        return bool(self.regex.search(text))


# ─────────────────────────────────────────────────────────────────────────────
# Traversal Check Module
# ─────────────────────────────────────────────────────────────────────────────


class TraversalCheckModule(BaseScannerModule):
    """
    Path Traversal / LFI detection module.

    Injects directory traversal sequences into URL query parameters and
    inspects response bodies for OS file content (``/etc/passwd``, ``win.ini``).
    Baseline comparison prevents false positives on error pages.
    """

    name: str = "traversal_check"
    description: str = (
        "Detects Path Traversal / LFI by injecting directory traversal sequences "
        "into URL query parameters and matching response bodies against OS-artifact "
        "patterns (e.g. /etc/passwd, win.ini)."
    )

    def __init__(self, requester: Requester) -> None:
        super().__init__(requester)
        self._probes: List[Dict] = []
        self._patterns: List[_DetectionPattern] = []
        self._load_payloads()

    # ── Payload loading ───────────────────────────────────────────────────────

    def _load_payloads(self) -> None:
        """Load probes and detection patterns from ``traversal_probes.json``."""
        try:
            with open(_TRAVERSAL_PROBES_PATH, encoding="utf-8") as fh:
                data: Dict = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.error("traversal_check: Failed to load payload file: %s", exc)
            return

        self._probes = data.get("probes", [])
        raw_patterns = data.get("detection_patterns", [])
        for raw in raw_patterns:
            try:
                self._patterns.append(_DetectionPattern(raw))
            except re.error as exc:
                logger.warning(
                    "traversal_check: Invalid regex in pattern %r: %s",
                    raw.get("id"), exc,
                )

        logger.debug(
            "traversal_check: Loaded %d probes and %d detection patterns.",
            len(self._probes), len(self._patterns),
        )

    # ── Body analysis ─────────────────────────────────────────────────────────

    def _matches_pattern(self, body: str) -> Optional[_DetectionPattern]:
        """
        Return the first matching detection pattern, or ``None``.

        Parameters
        ----------
        body : str
            HTTP response body text.

        Returns
        -------
        _DetectionPattern | None
            The first pattern whose regex matches ``body``, or ``None``.
        """
        for pattern in self._patterns:
            if pattern.matches(body):
                return pattern
        return None

    # ── URL manipulation ──────────────────────────────────────────────────────

    @staticmethod
    def _inject_param(url: str, param_name: str, value: str) -> str:
        """
        Return a copy of ``url`` with ``param_name`` replaced by ``value``.

        Other query parameters are preserved unchanged.

        Parameters
        ----------
        url : str
            The original URL.
        param_name : str
            The query parameter to replace.
        value : str
            The probe value to inject.

        Returns
        -------
        str
            Modified URL string.
        """
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param_name] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    # ── Core scan logic ───────────────────────────────────────────────────────

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        """
        Run traversal probes against ``endpoint``: every GET query/GET-form
        parameter (fuzzed via GET), and every POST form's own fields
        (fuzzed via POST against that form's own baseline).

        Parameters
        ----------
        endpoint : CrawledEndpoint
            Crawled endpoint to probe.

        Returns
        -------
        list[Finding]
            Confirmed path traversal / LFI findings.  Empty when no
            vulnerable parameters are discovered.
        """
        findings: List[Finding] = []

        if not self._probes or not self._patterns:
            logger.warning(
                "traversal_check: No probes or patterns loaded — skipping %s.",
                endpoint.url,
            )
            return findings

        # Track confirmed (url, param) pairs to avoid duplicate findings.
        confirmed: Set[Tuple[str, str]] = set()

        findings.extend(self._run_get_candidates(endpoint, confirmed))
        for form in endpoint.forms:
            if (getattr(form, "method", "GET") or "GET").upper() == "POST":
                findings.extend(self._run_post_form(form, confirmed))

        return findings

    # ── GET query/GET-form parameters ───────────────────────────────────────

    def _run_get_candidates(
        self, endpoint: CrawledEndpoint, confirmed: Set[Tuple[str, str]]
    ) -> List[Finding]:
        # Collect candidate parameters from the endpoint URL query string,
        # plus every GET-method form's fields.
        params: Dict[str, List[str]] = dict(endpoint.query_params)
        for form in endpoint.forms:
            if (getattr(form, "method", "GET") or "GET").upper() == "GET":
                for field in form.fields:
                    if field.name and field.name not in params:
                        params[field.name] = [field.default_value or ""]

        if not params:
            logger.debug(
                "traversal_check: No query params on %s — skipping.", endpoint.url
            )
            return []

        baseline_resp, baseline_err = self.requester.get(endpoint.url)
        if baseline_err or baseline_resp is None:
            logger.warning(
                "traversal_check: Baseline fetch failed for %s: %s",
                endpoint.url, baseline_err,
            )
            return []
        if baseline_resp.status_code >= 500:
            logger.debug(
                "traversal_check: Baseline %s returned HTTP %d — skipping.",
                endpoint.url, baseline_resp.status_code,
            )
            return []

        baseline_body: str = baseline_resp.text or ""
        baseline_match = self._matches_pattern(baseline_body)
        if baseline_match:
            logger.debug(
                "traversal_check: Baseline for %s already matches pattern %r — "
                "skipping to avoid false positives.",
                endpoint.url, baseline_match.id,
            )
            return []

        findings: List[Finding] = []
        for param_name in list(params.keys()):
            finding = self._probe_param(
                send=lambda v, p=param_name: self.requester.get(
                    self._inject_param(endpoint.url, p, v)
                ),
                param_name=param_name,
                report_url=endpoint.url,
                confirmed=confirmed,
                method="GET",
            )
            if finding:
                findings.append(finding)
        return findings

    # ── POST form fields ────────────────────────────────────────────────────

    def _run_post_form(
        self, form: ParsedForm, confirmed: Set[Tuple[str, str]]
    ) -> List[Finding]:
        base_body: Dict[str, str] = {
            f.name: (f.default_value or "") for f in form.fields if f.name
        }
        if not base_body:
            return []

        baseline_resp, baseline_err = self.requester.post(form.action_url, data=base_body)
        if baseline_err or baseline_resp is None:
            logger.warning(
                "traversal_check: POST baseline failed for %s: %s",
                form.action_url, baseline_err,
            )
            return []
        if baseline_resp.status_code >= 500:
            return []

        baseline_body: str = baseline_resp.text or ""
        if self._matches_pattern(baseline_body):
            logger.debug(
                "traversal_check: POST baseline for %s already matches a "
                "pattern — skipping to avoid false positives.",
                form.action_url,
            )
            return []

        findings: List[Finding] = []
        for field_name in base_body:
            finding = self._probe_param(
                send=lambda v, f=field_name: self.requester.post(
                    form.action_url, data={**base_body, f: v}
                ),
                param_name=field_name,
                report_url=form.action_url,
                confirmed=confirmed,
                method="POST",
            )
            if finding:
                findings.append(finding)
        return findings

    # ── Shared probe loop ────────────────────────────────────────────────────

    def _probe_param(
        self,
        send: Any,
        param_name: str,
        report_url: str,
        confirmed: Set[Tuple[str, str]],
        method: str,
    ) -> Optional[Finding]:
        """Try each probe via ``send(probe_value)`` until one confirms traversal."""
        if (report_url, param_name) in confirmed:
            return None

        for probe in self._probes:
            probe_value: str = probe["value"]
            response, error = send(probe_value)

            if error or response is None:
                logger.debug(
                    "traversal_check: Error probing %s %s=%r: %s",
                    report_url, param_name, probe_value, error,
                )
                continue
            if response.status_code >= 500:
                continue  # Skip server errors — too noisy.

            body = response.text or ""
            matched_pattern = self._matches_pattern(body)
            if matched_pattern is None:
                continue  # No pattern match — move to next probe.

            # Confirmed: pattern matched in fuzzed response but not baseline.
            confirmed.add((report_url, param_name))
            logger.info(
                "traversal_check: CONFIRMED LFI | %s | %s param=%r | "
                "probe=%r | pattern=%r",
                report_url, method, param_name, probe_value, matched_pattern.id,
            )

            return Finding(
                title="Path Traversal / Local File Inclusion (LFI)",
                severity=Severity.HIGH,
                confidence=Confidence.CERTAIN,
                url=report_url,
                parameter=param_name,
                payload=probe_value,
                evidence=(
                    f"Probe {probe['id']!r} injected into {method} parameter "
                    f"{param_name!r} triggered detection pattern "
                    f"{matched_pattern.id!r} ({matched_pattern.description})."
                ),
                remediation=(
                    "Never pass user-controlled input directly to file system "
                    "APIs (open(), include(), require(), etc.). Validate and "
                    "whitelist allowed file names/paths against a known-good "
                    "list. Use realpath() / canonical path resolution and "
                    "assert the resolved path starts with the expected base "
                    "directory. Disable PHP allow_url_include and allow_url_fopen "
                    "where not required. Consider serving files through a "
                    "content-addressed API layer rather than passing paths "
                    "directly to the file system."
                ),
                cvss_vector=_CVSS_VECTOR_HIGH,
                cvss_score=_CVSS_SCORE_HIGH,
                extra={
                    "probe_id": probe["id"],
                    "pattern_id": matched_pattern.id,
                    "method": method,
                    "module": self.name,
                },
            )

        return None
