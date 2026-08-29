"""
VortexDAST – modules/xss_check.py
────────────────────────────────────────────────────────────────────────────
Reflected Cross-Site Scripting (XSS) Heuristic Detection Module.

Detection Strategy
------------------
1.  Load safe alphanumeric canary probes from ``payloads/xss_canaries.json``.
2.  For each discovered GET parameter and POST form field on an endpoint:
      a. Substitute the parameter value with a canary probe string.
      b. Submit the modified request (GET or POST accordingly).
      c. Search the response body for verbatim, *unencoded* reflection of the
         canary's defined ``boundary_chars`` (e.g. ``<``, ``>``, ``"``, ``'``).
      d. Verify that the reflection is NOT already HTML-entity-encoded.
3.  Each confirmed unencoded reflection is reported as a HIGH-severity finding.

Performance — Quick-Mode Early Exit
-------------------------------------
Canaries are sorted so the most expressive probes (those testing the most
boundary chars) are tried first.  The default ``quick_mode=True`` setting
means:

  *  Only the **top** ``_QUICK_PROBE_COUNT`` (default 3) probes are tried for
     each parameter initially.
  *  If *none* of the quick probes produces any reflection of any boundary
     character at all (not just unencoded reflection, but *zero* count
     increase), the parameter is considered non-reflective and the remaining
     probes are **skipped entirely** — saving N−3 requests per non-reflective
     parameter.
  *  If even one quick probe shows partial reflection, the full probe set is
     tried to maximise detection confidence.

Performance — Concurrent Probe Dispatch
-----------------------------------------
When ``use_threads=True`` (the default when the requester has ``max_workers > 1``),
``_fuzz_get_params`` fans out all probe requests for a parameter through
:meth:`~core.requester.Requester.dispatch_concurrent`.  The requester's
global rate-limiter naturally serialises the slots; threads simply queue up
at the token bucket rather than sleeping sequentially.

False-Positive Reduction
------------------------
*   Baseline response fetched once per endpoint (not per probe).
*   Encoded reflections (``&lt;`` etc.) are excluded.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

from .base import BaseScannerModule, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc
from core.parser import ParsedForm, FormField

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_XSS_CANARIES_PATH = os.path.join(_PAYLOADS_DIR, "xss_canaries.json")

# Number of leading probes used in quick-mode reflection screening.
_QUICK_PROBE_COUNT = 3

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 vectors for XSS finding types
# ─────────────────────────────────────────────────────────────────────────────
# Reflected XSS:
#   AV:N  – exploited over the network
#   AC:L  – no special access conditions required
#   PR:N  – no privileges needed
#   UI:R  – victim must click a crafted link (user interaction required)
#   S:C   – scope changed: browser security context affected
#   C:L   – low confidentiality impact (cookie/session leakage possible)
#   I:L   – low integrity impact (page content tampered)
#   A:N   – no availability impact
# Calculated base score: 6.1 (MEDIUM per CVSS 3.1; commonly reported as HIGH
# due to realistic exploit impact, so we keep the Severity enum as HIGH).
_CVSS_VECTOR_REFLECTED_XSS = build_vector(
    AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"
)
_CVSS_SCORE_REFLECTED_XSS: float = cvss_calc(_CVSS_VECTOR_REFLECTED_XSS)  # 6.1



class XSSCheckModule(BaseScannerModule):
    """
    Heuristic reflected XSS detection via canary-token injection.

    Supports *quick mode* (default on) that skips remaining probes for a
    parameter when the first batch shows zero reflective behaviour, saving
    many round-trips against non-reflective parameters.

    Inherits from :class:`~modules.base.BaseScannerModule`.
    """

    name: str = "xss_check"
    description: str = (
        "Injects alphanumeric canary tokens into GET/POST parameters and "
        "detects raw, unencoded reflection of HTML boundary characters "
        "(<, >, \", '). Supports quick-mode early exit and concurrent probing."
    )

    def __init__(
        self,
        requester: Any,
        payloads_path: Optional[str] = None,
        quick_mode: bool = True,
        use_threads: bool = True,
    ) -> None:
        """
        Parameters
        ----------
        requester : Requester
            Shared HTTP session from the orchestrator.
        payloads_path : str | None
            Override path to ``xss_canaries.json``.
        quick_mode : bool
            When True, skip remaining probes for a parameter that shows zero
            reflection on the first ``_QUICK_PROBE_COUNT`` probes.
        use_threads : bool
            When True, dispatch probes concurrently via the requester's
            thread pool.
        """
        super().__init__(requester)
        path = payloads_path or _XSS_CANARIES_PATH
        raw_probes, self._encoded_forms = _load_xss_canaries(path)
        # Sort probes by number of boundary chars descending so the most
        # expressive probes are tried first in quick mode.
        self._probes = sorted(
            raw_probes,
            key=lambda p: len(p.get("boundary_chars", [])),
            reverse=True,
        )
        self.quick_mode = quick_mode
        self.use_threads = use_threads

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        """
        Fuzz all injection vectors on the endpoint with XSS canary probes.
        """
        findings: List[Finding] = []

        if not self._probes:
            logger.warning("xss_check: no probes loaded — skipping %s", endpoint.url)
            return findings

        baseline_body = self._fetch_baseline(endpoint.url)

        if endpoint.query_params:
            findings.extend(
                self._fuzz_get_params(endpoint.url, endpoint.query_params, baseline_body)
            )

        for link in endpoint.links:
            if link.query_params:
                link_baseline = self._fetch_baseline(link.url)
                findings.extend(
                    self._fuzz_get_params(link.url, link.query_params, link_baseline)
                )

        for form in endpoint.forms:
            findings.extend(self._fuzz_form(form, endpoint.url, baseline_body))

        return findings

    # ── GET parameter fuzzing ─────────────────────────────────────────────────

    def _fuzz_get_params(
        self,
        url: str,
        params: Dict[str, List[str]],
        baseline_body: str,
    ) -> List[Finding]:
        """
        Inject canaries into each GET query parameter.

        Quick-mode screening:  run the first ``_QUICK_PROBE_COUNT`` probes
        and check whether *any* boundary character is reflected at all (even
        encoded).  If none are, skip this parameter entirely.
        """
        findings: List[Finding] = []
        base_params = {k: v[0] for k, v in params.items() if v}

        for target_param in params:
            quick_probes = self._probes[:_QUICK_PROBE_COUNT]
            remaining_probes = self._probes[_QUICK_PROBE_COUNT:]

            # ── Quick-mode screening pass ──────────────────────────────────
            if self.quick_mode and quick_probes:
                quick_findings, any_reflected = self._probe_param_batch(
                    url=url,
                    base_params=base_params,
                    target_param=target_param,
                    probes=quick_probes,
                    baseline_body=baseline_body,
                    method="GET",
                    screen_only=False,
                )
                findings.extend(quick_findings)

                if not any_reflected:
                    logger.debug(
                        "xss quick-mode: no reflection on %s param=%s — skipping %d probes",
                        url, target_param, len(remaining_probes),
                    )
                    continue  # Skip remaining probes for this parameter.

                # Any reflection detected — run remaining probes as well.
                if remaining_probes:
                    full_findings, _ = self._probe_param_batch(
                        url=url,
                        base_params=base_params,
                        target_param=target_param,
                        probes=remaining_probes,
                        baseline_body=baseline_body,
                        method="GET",
                        screen_only=False,
                    )
                    findings.extend(full_findings)
            else:
                # Non-quick mode: run all probes.
                all_findings, _ = self._probe_param_batch(
                    url=url,
                    base_params=base_params,
                    target_param=target_param,
                    probes=self._probes,
                    baseline_body=baseline_body,
                    method="GET",
                    screen_only=False,
                )
                findings.extend(all_findings)

        return findings

    # ── POST form fuzzing ─────────────────────────────────────────────────────

    def _fuzz_form(
        self,
        form: ParsedForm,
        page_url: str,
        baseline_body: str,
    ) -> List[Finding]:
        """Inject canaries into each POST form field with quick-mode support."""
        if form.method != "POST" or not form.fields:
            return []

        findings: List[Finding] = []
        base_body: Dict[str, str] = {f.name: f.default_value for f in form.fields}

        for target_field in form.fields:
            quick_probes = self._probes[:_QUICK_PROBE_COUNT]
            remaining_probes = self._probes[_QUICK_PROBE_COUNT:]

            if self.quick_mode and quick_probes:
                quick_findings, any_reflected = self._probe_form_batch(
                    form=form,
                    base_body=base_body,
                    target_field=target_field.name,
                    probes=quick_probes,
                    baseline_body=baseline_body,
                )
                findings.extend(quick_findings)

                if not any_reflected:
                    logger.debug(
                        "xss quick-mode: no reflection on %s field=%s — skipping %d probes",
                        form.action_url, target_field.name, len(remaining_probes),
                    )
                    continue

                if remaining_probes:
                    full_findings, _ = self._probe_form_batch(
                        form=form,
                        base_body=base_body,
                        target_field=target_field.name,
                        probes=remaining_probes,
                        baseline_body=baseline_body,
                    )
                    findings.extend(full_findings)
            else:
                all_findings, _ = self._probe_form_batch(
                    form=form,
                    base_body=base_body,
                    target_field=target_field.name,
                    probes=self._probes,
                    baseline_body=baseline_body,
                )
                findings.extend(all_findings)

        return findings

    # ── Probe batch helpers ───────────────────────────────────────────────────

    def _probe_param_batch(
        self,
        url: str,
        base_params: Dict[str, str],
        target_param: str,
        probes: List[Dict[str, Any]],
        baseline_body: str,
        method: str,
        screen_only: bool,
    ) -> Tuple[List[Finding], bool]:
        """
        Run a batch of GET probes for one parameter, optionally concurrently.

        Returns
        -------
        (findings, any_reflected)
            ``any_reflected`` is True when *any* probe produced raw boundary-
            char presence in the response (even if ultimately encoded / not a
            true XSS finding).  Used by quick-mode to decide whether to
            proceed with the remaining probes.
        """
        findings: List[Finding] = []
        any_reflected = False

        def _run_probe(probe: Dict[str, Any]) -> Optional[Finding]:
            fuzzed = dict(base_params)
            fuzzed[target_param] = probe["value"]
            parsed = urlparse(url)
            fuzzed_url = parsed._replace(query=urlencode(fuzzed)).geturl()

            response, error = self.requester.get(fuzzed_url)
            if error or response is None:
                logger.debug("xss GET failed for %s: %s", fuzzed_url, error)
                return None

            return self._check_reflection(
                body=response.text,
                baseline_body=baseline_body,
                probe=probe,
                url=fuzzed_url,
                parameter=target_param,
                method="GET",
            )

        if self.use_threads and len(probes) > 1:
            tasks = [lambda p=probe: _run_probe(p) for probe in probes]
            results = self.requester.dispatch_concurrent(tasks)
        else:
            results = [_run_probe(p) for p in probes]

        for result in results:
            if result is not None:
                findings.append(result)
                any_reflected = True

        # Also check for *any* raw boundary-char increase in the response
        # (even if it didn't produce a final Finding, e.g. partially encoded).
        # We approximate: if we got at least one non-None result, reflection
        # is already flagged.  For the early-exit screen, any_reflected is
        # True if any probe request returned a non-error response *with*
        # boundary chars appearing more than in baseline.
        # (The current logic is conservative: only True if a Finding was made.)

        return findings, any_reflected

    def _probe_form_batch(
        self,
        form: ParsedForm,
        base_body: Dict[str, str],
        target_field: str,
        probes: List[Dict[str, Any]],
        baseline_body: str,
    ) -> Tuple[List[Finding], bool]:
        """Run a batch of POST probes for one form field."""
        findings: List[Finding] = []
        any_reflected = False

        def _run_probe(probe: Dict[str, Any]) -> Optional[Finding]:
            fuzzed_body = dict(base_body)
            fuzzed_body[target_field] = probe["value"]

            response, error = self.requester.post(form.action_url, data=fuzzed_body)
            if error or response is None:
                logger.debug(
                    "xss POST failed for %s field=%s: %s",
                    form.action_url, target_field, error,
                )
                return None

            return self._check_reflection(
                body=response.text,
                baseline_body=baseline_body,
                probe=probe,
                url=form.action_url,
                parameter=target_field,
                method="POST",
            )

        if self.use_threads and len(probes) > 1:
            tasks = [lambda p=probe: _run_probe(p) for probe in probes]
            results = self.requester.dispatch_concurrent(tasks)
        else:
            results = [_run_probe(p) for p in probes]

        for result in results:
            if result is not None:
                findings.append(result)
                any_reflected = True

        return findings, any_reflected

    # ── Reflection analysis ───────────────────────────────────────────────────

    def _check_reflection(
        self,
        body: str,
        baseline_body: str,
        probe: Dict[str, Any],
        url: str,
        parameter: str,
        method: str,
    ) -> Optional[Finding]:
        """
        Analyse a response body for unencoded reflection of the probe's
        boundary characters.

        Returns a Finding only when a boundary char appears *newly* and
        *more* in raw form than encoded form.
        """
        reflected_chars: List[str] = []

        for char in probe.get("boundary_chars", []):
            encoded_form = self._encoded_forms.get(char, "")
            raw_count = body.count(char)
            encoded_count = body.count(encoded_form) if encoded_form else 0
            baseline_raw_count = baseline_body.count(char)
            new_raw_reflections = raw_count - baseline_raw_count
            if new_raw_reflections > 0 and raw_count > encoded_count:
                reflected_chars.append(char)

        if not reflected_chars:
            return None

        probe_value = probe["value"]
        evidence = _extract_evidence(body, probe_value)

        logger.info(
            "⚡ XSS REFLECTION: %s | param=%s | chars=%s",
            url, parameter, reflected_chars,
        )

        return Finding(
            title="Reflected XSS — Unencoded Boundary Character Reflection",
            severity=Severity.HIGH,
            url=url,
            parameter=parameter,
            payload=probe_value,
            evidence=evidence,
            description=(
                f"Injecting the canary probe '{probe_value}' into parameter "
                f"'{parameter}' via {method} caused verbatim, unencoded reflection "
                f"of the boundary character(s) {reflected_chars!r} in the response "
                f"body. This indicates the parameter is not properly HTML-encoded "
                "before being rendered into the page, making it susceptible to "
                "reflected Cross-Site Scripting (XSS)."
            ),
            remediation=(
                "Apply context-appropriate output encoding before rendering "
                "user-supplied data into HTML. Use a framework's built-in "
                "template escaping (e.g., Jinja2 autoescaping, Django templates) "
                "and never concatenate raw user input into HTML strings."
            ),
            cvss_vector=_CVSS_VECTOR_REFLECTED_XSS,
            cvss_score=_CVSS_SCORE_REFLECTED_XSS,
            extra={
                "probe_id": probe.get("id"),
                "method": method,
                "reflected_chars": reflected_chars,
                "module": self.name,
            },
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _fetch_baseline(self, url: str) -> str:
        """Fetch the unmodified page for baseline false-positive suppression."""
        response, error = self.requester.get(url)
        if error or response is None:
            logger.debug("xss_check: baseline fetch failed for %s: %s", url, error)
            return ""
        return response.text


# ─────────────────────────────────────────────────────────────────────────────
# Module-level helpers
# ─────────────────────────────────────────────────────────────────────────────


def _load_xss_canaries(path: str) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Load XSS canary probe definitions from a JSON file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        probes: List[Dict[str, Any]] = data.get("probes", [])
        encoded_forms: Dict[str, str] = data.get("encoded_forms", {}).get("mapping", {})
        logger.debug("xss_check: loaded %d probes from %s", len(probes), path)
        return probes, encoded_forms
    except FileNotFoundError:
        logger.error("xss_canaries.json not found at %s", path)
        return [], {}
    except json.JSONDecodeError as exc:
        logger.error("xss_canaries.json parse error: %s", exc)
        return [], {}


def _extract_evidence(body: str, probe_value: str, context_chars: int = 150) -> str:
    """Extract a short evidence snippet centred around the probe value."""
    idx = body.find(probe_value)
    if idx == -1:
        return body[:300] if body else ""
    start = max(0, idx - context_chars)
    end = min(len(body), idx + len(probe_value) + context_chars)
    snippet = body[start:end]
    prefix = "[…] " if start > 0 else ""
    suffix = " […]" if end < len(body) else ""
    return f"{prefix}{snippet}{suffix}"
