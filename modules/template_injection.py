"""
VortexDAST – modules/template_injection.py
────────────────────────────────────────────────────────────────────────────
Server-Side Template Injection (SSTI) Heuristic Detection Module.

Detection Strategy
------------------
1.  Load arithmetic polyglot probes from ``payloads/ssti_probes.json``. Each
    probe wraps a distinctive multiplication (``191*7 = 1337``) inside the
    expression syntax of one or more template engines (Jinja2, Twig, FreeMarker,
    Velocity, Smarty, ERB, Razor, …), surrounded by a unique marker so the
    reflection can be anchored precisely.
2.  For each discovered GET parameter and POST form field:
      a. Fetch a **baseline** response with the original value so the computed
         result is not mistaken for pre-existing page content.
      b. Inject each probe's ``value`` into the parameter.
      c. Compare the response against two mutually-exclusive outcomes:
           *  ``expected`` marker present (e.g. ``vtxSSTI1337ENDvtx``) and absent
              from the baseline  →  the engine **evaluated** the expression →
              confirmed SSTI (HIGH / FIRM).
           *  only the ``literal`` probe reflected  →  input was echoed but NOT
              evaluated  →  **no finding** (safe; this is the key false-positive
              guard that separates SSTI from plain reflection / XSS).

False-Positive Reduction
------------------------
*   The computed product (``1337``) is wrapped in an uncommon marker so a page
    coincidentally containing "1337" does not trigger a finding.
*   Evaluation must be *new* relative to the baseline response.
*   Literal (non-evaluated) reflection is explicitly ignored.

Safety
------
*   Probes compute a harmless arithmetic expression only. No OS command,
    file access, or object-traversal payload is ever sent.

Performance
-----------
*   One baseline request per parameter, not per probe.
*   Short-circuits a parameter after the first confirmed evaluation.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc
from core.parser import ParsedForm

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_SSTI_PROBES_PATH = os.path.join(_PAYLOADS_DIR, "ssti_probes.json")

# Confirmed SSTI (expression evaluated server-side): network-exploitable, low
# complexity, no privileges/UI. SSTI commonly escalates to RCE, so C/I/A High.
# AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:H  → 9.8 (CRITICAL base)
_CVSS_VECTOR_SSTI = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"
)
_CVSS_SCORE_SSTI: float = cvss_calc(_CVSS_VECTOR_SSTI)


class TemplateInjectionModule(BaseScannerModule):
    """
    Heuristic Server-Side Template Injection detection module.

    Injects benign arithmetic template expressions into discovered parameters
    and reports a finding only when the engine returns the *computed* result,
    proving server-side evaluation.

    Inherits from :class:`~modules.base.BaseScannerModule`.
    """

    name: str = "template_injection"
    description: str = (
        "Injects benign arithmetic template expressions (Jinja2, Twig, "
        "FreeMarker, Velocity, Smarty, ERB, Razor) into GET and POST "
        "parameters and reports Server-Side Template Injection when the "
        "engine evaluates the expression."
    )

    def __init__(self, requester: Any, payloads_path: Optional[str] = None) -> None:
        super().__init__(requester)
        path = payloads_path or _SSTI_PROBES_PATH
        self._probes = _load_ssti_probes(path)

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        findings: List[Finding] = []

        if not self._probes:
            logger.warning(
                "template_injection: no probes loaded — skipping %s", endpoint.url
            )
            return findings

        if endpoint.query_params:
            findings.extend(
                self._fuzz_get_params(endpoint.url, endpoint.query_params)
            )

        for link in endpoint.links:
            link_params = getattr(link, "query_params", None)
            if link_params:
                findings.extend(self._fuzz_get_params(link.url, link_params))

        for form in endpoint.forms:
            findings.extend(self._fuzz_form(form))

        return findings

    # ── GET parameter fuzzing ─────────────────────────────────────────────────

    def _fuzz_get_params(
        self, url: str, params: Dict[str, List[str]]
    ) -> List[Finding]:
        findings: List[Finding] = []
        base_params = {k: v[0] for k, v in params.items() if v}

        for target_param, original_values in params.items():
            original_value = original_values[0] if original_values else ""

            baseline_body = self._fetch_get_baseline(url, base_params)
            if baseline_body is None:
                continue

            for probe in self._probes:
                fuzzed_params = dict(base_params)
                fuzzed_params[target_param] = original_value + probe["value"]
                parsed = urlparse(url)
                fuzzed_url = parsed._replace(query=urlencode(fuzzed_params)).geturl()

                response, error = self.requester.get(fuzzed_url)
                if error or response is None:
                    logger.debug(
                        "ssti GET failed %s param=%s: %s",
                        fuzzed_url, target_param, error,
                    )
                    continue

                finding = self._analyse_response(
                    fuzzed_body=response.text,
                    baseline_body=baseline_body,
                    probe=probe,
                    url=fuzzed_url,
                    parameter=target_param,
                    method="GET",
                )
                if finding:
                    findings.append(finding)
                    break  # One confirmed evaluation per parameter is enough.

        return findings

    # ── POST form fuzzing ─────────────────────────────────────────────────────

    def _fuzz_form(self, form: ParsedForm) -> List[Finding]:
        if not form.fields:
            return []

        findings: List[Finding] = []
        base_body: Dict[str, str] = {f.name: f.default_value for f in form.fields}

        for target_field in form.fields:
            original_value = target_field.default_value

            baseline_body = self._fetch_post_baseline(form.action_url, base_body)
            if baseline_body is None:
                continue

            for probe in self._probes:
                fuzzed_body = dict(base_body)
                fuzzed_body[target_field.name] = original_value + probe["value"]

                response, error = self.requester.post(
                    form.action_url, data=fuzzed_body
                )
                if error or response is None:
                    logger.debug(
                        "ssti POST failed %s field=%s: %s",
                        form.action_url, target_field.name, error,
                    )
                    continue

                finding = self._analyse_response(
                    fuzzed_body=response.text,
                    baseline_body=baseline_body,
                    probe=probe,
                    url=form.action_url,
                    parameter=target_field.name,
                    method="POST",
                )
                if finding:
                    findings.append(finding)
                    break

        return findings

    # ── Core response analyser ────────────────────────────────────────────────

    def _analyse_response(
        self,
        fuzzed_body: str,
        baseline_body: str,
        probe: Dict[str, Any],
        url: str,
        parameter: str,
        method: str,
    ) -> Optional[Finding]:
        """
        Report SSTI only when the computed ``expected`` marker is present in the
        fuzzed response and absent from the baseline. Literal reflection of the
        un-evaluated probe is deliberately ignored.
        """
        expected = probe["expected"]

        if expected not in fuzzed_body:
            return None

        # Guard: the marked result must be *new* relative to the baseline.
        if expected in baseline_body:
            return None

        engines = ", ".join(probe.get("engines", [])) or "unknown engine"
        snippet = _extract_snippet(fuzzed_body, expected)

        logger.info(
            "⚡ SSTI: %s | param=%s | probe=%s | engines=%s",
            url, parameter, probe.get("id"), engines,
        )

        return Finding(
            title="Server-Side Template Injection — Expression Evaluated",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            parameter=parameter,
            payload=probe["value"],
            evidence=snippet,
            description=(
                f"Injecting the template expression '{probe['value']}' into "
                f"parameter '{parameter}' via {method} caused the server to return "
                f"the evaluated result ('{expected}'). The arithmetic '191*7' was "
                "computed server-side, which confirms that user input is rendered "
                f"as a template. Compatible engine(s): {engines}.\n\n"
                "Server-Side Template Injection frequently escalates to remote code "
                "execution via engine-specific object traversal."
            ),
            remediation=(
                "Never pass user-controlled input into a template as part of the "
                "template source. Render untrusted data strictly as context "
                "variables/data, not as template markup. Where dynamic templates "
                "are unavoidable, use a sandboxed engine configuration and an "
                "allow-list of permitted expressions."
            ),
            cvss_vector=_CVSS_VECTOR_SSTI,
            cvss_score=_CVSS_SCORE_SSTI,
            extra={
                "engines": probe.get("engines", []),
                "probe_id": probe.get("id"),
                "evaluated_result": expected,
                "method": method,
                "module": self.name,
            },
        )

    # ── Baseline helpers ──────────────────────────────────────────────────────

    def _fetch_get_baseline(
        self, url: str, params: Dict[str, str]
    ) -> Optional[str]:
        parsed = urlparse(url)
        baseline_url = parsed._replace(query=urlencode(params)).geturl()
        response, error = self.requester.get(baseline_url)
        if error or response is None:
            logger.debug("ssti GET baseline failed for %s: %s", baseline_url, error)
            return None
        return response.text

    def _fetch_post_baseline(
        self, url: str, data: Dict[str, str]
    ) -> Optional[str]:
        response, error = self.requester.post(url, data=data)
        if error or response is None:
            logger.debug("ssti POST baseline failed for %s: %s", url, error)
            return None
        return response.text


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _extract_snippet(body: str, needle: str, pad: int = 80) -> str:
    """Return a context window around the first occurrence of ``needle``."""
    idx = body.find(needle)
    if idx == -1:
        return needle
    start = max(0, idx - pad)
    end = min(len(body), idx + len(needle) + pad)
    return body[start:end]


def _load_ssti_probes(path: str) -> List[Dict[str, Any]]:
    """Load and validate SSTI probe definitions from JSON."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.error("ssti_probes.json not found at %s", path)
        return []
    except json.JSONDecodeError as exc:
        logger.error("ssti_probes.json parse error: %s", exc)
        return []

    probes: List[Dict[str, Any]] = []
    for probe in data.get("probes", []):
        if probe.get("value") and probe.get("expected"):
            probes.append(probe)
        else:
            logger.warning("ssti_check: skipping malformed probe %s", probe.get("id"))

    logger.debug("template_injection: loaded %d probes from %s", len(probes), path)
    return probes
