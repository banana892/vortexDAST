"""
VortexDAST – modules/command_injection_check.py
────────────────────────────────────────────────────────────────────────────
OS Command Injection detection module (OWASP A03:2021 / CWE-78).

Detection Strategy
------------------
Every GET parameter, link parameter, and POST form field is fuzzed (no
name-gating — unlike SSRF/open-redirect, a shell metacharacter can land in
*any* parameter a vulnerable app happens to pass to a shell). Each probe
appends a command-separator + a harmless, read-only command to the
parameter's *original* value, the same append-don't-replace technique
``sqli_check`` uses for its boundary probes.

1.  **Output-based (``output_probes``)** — chains onto a command whose
    output is distinctive and easy to recognise (``id``, ``ver``) using five
    separator styles (``;``, ``|``, ``&&``, backtick, ``$()``). A hit
    requires *every* marker regex for that probe to match the fuzzed
    response — and *none* of them to already match the unmodified baseline,
    so a page that naturally prints something marker-shaped is not flagged.
    Reported at ``HIGH``/``FIRM`` — captured command output is direct proof
    of execution.
2.  **Time-based blind (``time_based_probes``)** — chains onto ``sleep``
    (*nix) or ``ping`` (Windows, no native sleep) using the same five
    separator styles. Exactly ``sqli_check``'s time-based-blind machinery:
    a hit needs the measured delay to clear both a relative (60 % of the
    probe's own injected delay) and an absolute (2 s) threshold, *and*
    reproduce on a second confirmation request, so ordinary network/CDN
    jitter cannot masquerade as an injected delay. Reported at
    ``HIGH``/``FIRM``.

Safety
------
Every command is read-only and non-destructive (``id``, ``ver``, ``sleep``,
``ping -n``) — no write, delete, or state-changing action is ever sent. This
is the same safety bar real pentest/DAST tooling (Burp, OWASP ZAP, commix)
uses for this class: proving execution does not require anything harmful.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Pattern, Tuple
from urllib.parse import urlencode, urlparse

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc
from core.parser import ParsedForm

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_CMDI_PROBES_PATH = os.path.join(_PAYLOADS_DIR, "command_injection_probes.json")

# Time-based blind: same false-positive-safe thresholds as sqli_check's.
_TIME_BASED_DELAY_FRACTION = 0.6
_TIME_BASED_MIN_DELTA_SECONDS = 2.0

# Confirmed OS command execution (output captured or a reproduced timing
# oracle) — full compromise of the host the app runs on.
# AV:N / AC:L / PR:N / UI:N / S:C / C:H / I:H / A:H → 10.0 (CRITICAL by the
# score table, but this project labels its most severe confirmed findings
# HIGH — same convention sqli_check/ssrf_check use for their top tier).
_CVSS_VECTOR_CMDI = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"
)
_CVSS_SCORE_CMDI: float = cvss_calc(_CVSS_VECTOR_CMDI)


class CommandInjectionCheckModule(BaseScannerModule):
    """OS command-injection detection via output capture and timing oracles."""

    name: str = "command_injection_check"
    description: str = (
        "Detects OS command injection by appending separator + harmless "
        "command (id/ver, sleep/ping) to every parameter and watching for "
        "captured command output or a reproduced timing delay."
    )

    def __init__(self, requester: Any, payloads_path: Optional[str] = None) -> None:
        super().__init__(requester)
        path = payloads_path or _CMDI_PROBES_PATH
        self._output_probes, self._time_based_probes = _load_cmdi_probes(path)
        self._compiled_markers: Dict[str, List[Pattern[str]]] = {
            probe["id"]: [re.compile(m, re.IGNORECASE) for m in probe.get("markers", [])]
            for probe in self._output_probes
        }

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        findings: List[Finding] = []

        if not self._output_probes and not self._time_based_probes:
            logger.warning("command_injection_check: no probes loaded — skipping %s", endpoint.url)
            return findings

        if endpoint.query_params:
            findings.extend(self._fuzz_get_params(endpoint.url, endpoint.query_params))

        for link in endpoint.links:
            if link.query_params:
                findings.extend(self._fuzz_get_params(link.url, link.query_params))

        for form in endpoint.forms:
            findings.extend(self._fuzz_form(form))

        return findings

    # ── GET parameter fuzzing ─────────────────────────────────────────────────

    def _fuzz_get_params(self, url: str, params: Dict[str, List[str]]) -> List[Finding]:
        findings: List[Finding] = []
        base_params = {k: v[0] for k, v in params.items() if v}

        for target_param, original_values in params.items():
            original_value = original_values[0] if original_values else ""

            baseline_resp, baseline_err = self.requester.get(_build_url(url, base_params))
            if baseline_err or baseline_resp is None:
                continue
            baseline_body = baseline_resp.text or ""
            baseline_elapsed = baseline_resp.elapsed.total_seconds()

            output_finding = self._output_based_check(
                lambda fuzzed_url: self.requester.get(fuzzed_url),
                url, base_params, target_param, original_value, baseline_body, method="GET",
            )
            if output_finding:
                findings.append(output_finding)

            time_finding = self._time_based_check(
                lambda fuzzed_url: self.requester.get(fuzzed_url),
                url, base_params, target_param, original_value, baseline_elapsed, method="GET",
            )
            if time_finding:
                findings.append(time_finding)

        return findings

    # ── POST form fuzzing ─────────────────────────────────────────────────────

    def _fuzz_form(self, form: ParsedForm) -> List[Finding]:
        findings: List[Finding] = []
        base_body = {f.name: f.default_value for f in form.fields}

        for target_field in base_body:
            original_value = base_body.get(target_field, "")

            baseline_resp, baseline_err = self.requester.post(form.action_url, data=base_body)
            if baseline_err or baseline_resp is None:
                continue
            baseline_body = baseline_resp.text or ""
            baseline_elapsed = baseline_resp.elapsed.total_seconds()

            output_finding = self._output_based_check(
                lambda body: self.requester.post(form.action_url, data=body),
                form.action_url, base_body, target_field, original_value, baseline_body, method="POST",
            )
            if output_finding:
                findings.append(output_finding)

            time_finding = self._time_based_check(
                lambda body: self.requester.post(form.action_url, data=body),
                form.action_url, base_body, target_field, original_value, baseline_elapsed, method="POST",
            )
            if time_finding:
                findings.append(time_finding)

        return findings

    # ── Output-based detection ─────────────────────────────────────────────────

    def _output_based_check(
        self,
        send: Any,
        url: str,
        base_data: Dict[str, str],
        target: str,
        original_value: str,
        baseline_body: str,
        *,
        method: str,
    ) -> Optional[Finding]:
        for probe in self._output_probes:
            fuzzed_data = dict(base_data)
            fuzzed_data[target] = original_value + probe["value"]
            fuzzed_target: Any = _build_url(url, fuzzed_data) if method == "GET" else fuzzed_data

            resp, err = send(fuzzed_target)
            if err or resp is None:
                continue

            patterns = self._compiled_markers.get(probe["id"], [])
            fuzzed_body = resp.text or ""
            if not patterns or not all(p.search(fuzzed_body) for p in patterns):
                continue
            if all(p.search(baseline_body) for p in patterns):
                continue  # already present unmodified — not injection-caused

            report_url = fuzzed_target if method == "GET" else url
            return self._output_finding(report_url, target, probe, fuzzed_body, method)

        return None

    def _output_finding(
        self, url: str, parameter: str, probe: Dict[str, Any], fuzzed_body: str, method: str
    ) -> Finding:
        logger.info("⚡ Command Injection (output): %s | param=%s | probe=%s", url, parameter, probe["id"])
        evidence_snippet = (fuzzed_body[:300] + " […]") if len(fuzzed_body) > 300 else fuzzed_body
        return Finding(
            title="OS Command Injection — Confirmed via Captured Output",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            parameter=parameter,
            payload=probe["value"],
            evidence=evidence_snippet,
            description=(
                f"Appending '{probe['value']}' to the '{parameter}' {method} "
                f"parameter ({probe['description']}) caused the response to "
                "contain the output of an OS command that was never part of "
                "the application's own output — proof the server executed "
                "attacker-supplied shell input."
            ),
            remediation=(
                "Never pass user input to a shell. Use the language's native "
                "API for the underlying operation instead of shelling out "
                "(e.g. a library DNS resolver instead of `ping`). Where a "
                "subprocess is unavoidable, invoke it with an argv list (never "
                "shell=True on an interpolated string) and strictly allowlist "
                "the input."
            ),
            cvss_vector=_CVSS_VECTOR_CMDI,
            cvss_score=_CVSS_SCORE_CMDI,
            extra={"probe_id": probe.get("id"), "probe_value": probe["value"], "method": method, "module": self.name},
        )

    # ── Time-based blind detection ─────────────────────────────────────────────

    def _exceeds_delay_threshold(
        self, elapsed: float, baseline_elapsed: float, probe: Dict[str, Any]
    ) -> bool:
        delay = probe.get("delay_seconds", 0)
        threshold = max(delay * _TIME_BASED_DELAY_FRACTION, _TIME_BASED_MIN_DELTA_SECONDS)
        return (elapsed - baseline_elapsed) >= threshold

    def _time_based_check(
        self,
        send: Any,
        url: str,
        base_data: Dict[str, str],
        target: str,
        original_value: str,
        baseline_elapsed: float,
        *,
        method: str,
    ) -> Optional[Finding]:
        for probe in self._time_based_probes:
            fuzzed_data = dict(base_data)
            fuzzed_data[target] = original_value + probe["value"]
            fuzzed_target: Any = _build_url(url, fuzzed_data) if method == "GET" else fuzzed_data

            resp, err = send(fuzzed_target)
            if err or resp is None:
                continue
            elapsed = resp.elapsed.total_seconds()
            if not self._exceeds_delay_threshold(elapsed, baseline_elapsed, probe):
                continue

            confirm_resp, confirm_err = send(fuzzed_target)
            if confirm_err or confirm_resp is None:
                continue
            confirm_elapsed = confirm_resp.elapsed.total_seconds()
            if not self._exceeds_delay_threshold(confirm_elapsed, baseline_elapsed, probe):
                continue

            report_url = fuzzed_target if method == "GET" else url
            return self._time_finding(
                report_url, target, probe, elapsed, confirm_elapsed, baseline_elapsed, method
            )

        return None

    def _time_finding(
        self,
        url: str,
        parameter: str,
        probe: Dict[str, Any],
        elapsed: float,
        confirm_elapsed: float,
        baseline_elapsed: float,
        method: str,
    ) -> Finding:
        logger.info(
            "⚡ Command Injection (time-based blind): %s | param=%s | probe=%s | +%.2fs",
            url, parameter, probe["id"], elapsed - baseline_elapsed,
        )
        delay = probe.get("delay_seconds", 0)
        return Finding(
            title="OS Command Injection — Confirmed via Time-Based Blind Probe",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=url,
            parameter=parameter,
            payload=probe["value"],
            evidence=(
                f"Baseline response: {baseline_elapsed:.2f}s. First probe "
                f"(expected ~{delay}s extra): {elapsed:.2f}s. Reproduced on a "
                f"second confirmation request: {confirm_elapsed:.2f}s."
            ),
            description=(
                f"Appending '{probe['value']}' to the '{parameter}' {method} "
                f"parameter ({probe['description']}) reliably delayed the "
                "response by the injected amount, reproduced on a second "
                "request — ruling out ordinary network/CDN jitter — proving "
                "the server executed attacker-supplied shell input "
                "(blind: no output was captured, only the induced delay)."
            ),
            remediation=(
                "Never pass user input to a shell. Use the language's native "
                "API for the underlying operation instead of shelling out. "
                "Where a subprocess is unavoidable, invoke it with an argv "
                "list (never shell=True on an interpolated string) and "
                "strictly allowlist the input."
            ),
            cvss_vector=_CVSS_VECTOR_CMDI,
            cvss_score=_CVSS_SCORE_CMDI,
            extra={
                "probe_id": probe.get("id"),
                "probe_value": probe["value"],
                "delay_s": elapsed - baseline_elapsed,
                "confirm_delay_s": confirm_elapsed - baseline_elapsed,
                "method": method,
                "module": self.name,
            },
        )


# ─────────────────────────────────────────────────────────────────────────────
# Module-level helpers
# ─────────────────────────────────────────────────────────────────────────────


def _build_url(url: str, params: Dict[str, str]) -> str:
    parsed = urlparse(url)
    return parsed._replace(query=urlencode(params)).geturl()


def _load_cmdi_probes(path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.error("command_injection_probes.json not found at %s", path)
        return [], []
    except json.JSONDecodeError as exc:
        logger.error("command_injection_probes.json parse error: %s", exc)
        return [], []

    output_probes: List[Dict[str, Any]] = data.get("output_probes", [])
    time_based_probes: List[Dict[str, Any]] = data.get("time_based_probes", [])

    logger.debug(
        "command_injection_check: loaded %d output probes, %d time-based probes from %s",
        len(output_probes), len(time_based_probes), path,
    )
    return output_probes, time_based_probes
