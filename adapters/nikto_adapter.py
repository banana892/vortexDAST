"""
VortexDAST – adapters/nikto_adapter.py
────────────────────────────────────────────────────────────────────────────
Adapter for **nikto** — a web-server misconfiguration and known-dangerous-file
scanner, the Phase E tier-3 adapter after ffuf/nikto/subfinder/testssl.sh.

nikto only writes JSON to a **file**, never to stdout (its ``-output -``
doesn't mean "stdout" the way nmap's/ffuf's ``-`` does), so this adapter
overrides :meth:`run` to point it at a temp file and read that back —
everything else (argv-safe invocation, timeout, fallback, Finding mapping)
follows the same shape as every other adapter.

Invocation
----------
``nikto -h <target> -Format json -output <tmpfile> -maxtime <budget>s
-nointeractive -ask no``. ``-maxtime`` is derived from the adapter's own
timeout budget (minus a small buffer) so nikto stops itself and flushes
partial JSON before our own hard subprocess timeout would otherwise kill it
mid-write.

Severity mapping
-----------------
nikto's own JSON carries no severity at all — it's a high-recall heuristic
scanner that surfaces *candidates* for a human to triage, not confirmed
findings (its own documentation is explicit about this). Nearly everything
is therefore mapped as INFORMATIONAL/TENTATIVE; the one case treated more
seriously is a finding whose ``references`` field cites a CVE (a specific,
checkable claim rather than a generic header-hygiene note), bumped to
MEDIUM/FIRM.

Licence note
------------
nikto is GPL-licensed and invoked as a *separate program* (subprocess),
never imported — see IMPROVEMENTS.md §3.

Safety
------
The target reaches nikto only as a single argv element through
:func:`core.orchestrator.run_command` (``shell=False``). nikto is run with
its own default tuning (no flags added that would make it more aggressive
than its standard behaviour). **Only scan targets you are authorised to
test.**
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from core.cvss import build_vector, calculate as cvss_calc
from core.orchestrator import ScanContext, ToolAdapter, run_command
from modules.base import Confidence, Finding, Severity

logger = logging.getLogger(__name__)

# A CVE citation is a specific, checkable claim — more actionable than
# nikto's generic header-hygiene notes, but still unconfirmed (nikto didn't
# exploit anything, just matched a signature), so MEDIUM rather than higher.
_CVSS_VECTOR_NIKTO_CVE = build_vector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="N")
_CVSS_SCORE_NIKTO_CVE: float = cvss_calc(_CVSS_VECTOR_NIKTO_CVE)  # 6.5

#: Buffer subtracted from the timeout budget before handing nikto its own
#: -maxtime, so it has a moment to flush JSON before we'd otherwise kill it.
_MAXTIME_BUFFER_S = 15
_MIN_MAXTIME_S = 10


class NiktoAdapter(ToolAdapter):
    """Drive nikto (via a temp JSON file) and map its findings into Findings."""

    name: str = "nikto"
    binary: str = "nikto"
    description: str = (
        "Web-server misconfiguration / known-dangerous-file scanner. "
        "High-recall and heuristic — findings are candidates for review, "
        "not confirmed. Optional external tool."
    )
    default_timeout: float = 600.0

    def __init__(self) -> None:
        self._output_path: str = ""
        #: Stashed by run() so parse() can resolve nikto's path-only URLs
        #: against the scanned target.
        self._target: str = ""

    # ── ToolAdapter contract ──────────────────────────────────────────────

    def build_command(self, target: str, ctx: ScanContext) -> List[str]:
        """Argv for nikto, writing JSON to :attr:`_output_path`."""
        timeout = min(self.default_timeout, ctx.tool_timeout)
        maxtime = max(_MIN_MAXTIME_S, int(timeout) - _MAXTIME_BUFFER_S)
        return [
            self.binary,
            "-h",
            target,
            "-Format",
            "json",
            "-output",
            self._output_path or "nikto_output.json",
            "-maxtime",
            f"{maxtime}s",
            "-nointeractive",
            "-ask",
            "no",
        ]

    def parse(self, raw_output: str) -> List[Finding]:
        """Translate nikto's JSON (one object per scanned host) into Findings."""
        if not raw_output or not raw_output.strip():
            return []
        try:
            hosts = json.loads(raw_output)
        except (ValueError, TypeError) as exc:
            logger.debug("nikto adapter: could not parse output: %s", exc)
            return []
        if not isinstance(hosts, list):
            return []

        findings: List[Finding] = []
        for host_entry in hosts:
            if not isinstance(host_entry, dict):
                continue
            for vuln in host_entry.get("vulnerabilities") or []:
                finding = self._map_vulnerability(vuln)
                if finding is not None:
                    findings.append(finding)
        return findings

    # ── Orchestration entry point (overrides the subprocess-only default) ──
    # nikto has no stdout JSON mode, so the base class's "capture stdout,
    # parse it" flow doesn't apply — point it at a temp file instead.

    def run(self, target: str, ctx: ScanContext) -> List[Finding]:
        if not self.is_available():
            return self._fallback(target, ctx)

        self._target = target
        workdir = tempfile.mkdtemp(prefix="vortex-nikto-")
        self._output_path = os.path.join(workdir, "nikto.json")

        try:
            timeout = min(self.default_timeout, ctx.tool_timeout)
            argv = self.build_command(target, ctx)
            logger.debug("Running %s: %s", self.name, " ".join(argv))
            result = run_command(argv, timeout=timeout)

            if result.not_found:
                return self._fallback(target, ctx)
            if result.timed_out:
                logger.warning("Adapter 'nikto' timed out; checking for partial output.")
            elif result.returncode != 0:
                logger.warning(
                    "Adapter 'nikto' exited %d: %s",
                    result.returncode, result.stderr.strip()[:200],
                )

            raw = ""
            if os.path.isfile(self._output_path):
                with open(self._output_path, "r") as fh:
                    raw = fh.read()

            try:
                return self.parse(raw)
            except Exception as exc:  # pragma: no cover — defensive
                logger.error("Adapter 'nikto' failed to parse output: %s", exc)
                return []
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # ── Internal mapping ─────────────────────────────────────────────────

    def _map_vulnerability(self, vuln: Any) -> Optional[Finding]:
        if not isinstance(vuln, dict):
            return None
        msg = (vuln.get("msg") or "").strip()
        if not msg:
            return None

        path = vuln.get("url") or "/"
        url = urljoin(self._target, path) if self._target else path
        references = (vuln.get("references") or "").strip()
        is_cve = "CVE-" in references.upper()

        severity = Severity.MEDIUM if is_cve else Severity.INFORMATIONAL
        confidence = Confidence.FIRM if is_cve else Confidence.TENTATIVE

        evidence_parts = [f"id={vuln.get('id')}", f"method={vuln.get('method') or 'GET'}", f"path={path}"]
        if references:
            evidence_parts.append(f"ref={references}")

        return Finding(
            title=f"nikto: {msg[:97] + '...' if len(msg) > 100 else msg}",
            severity=severity,
            confidence=confidence,
            url=url,
            parameter=None,
            payload=None,
            evidence="; ".join(evidence_parts),
            description=msg,
            remediation=(
                "Review this finding manually before acting on it — nikto is "
                "a high-recall heuristic scanner and can false-positive."
            ),
            cvss_vector=_CVSS_VECTOR_NIKTO_CVE if is_cve else None,
            cvss_score=_CVSS_SCORE_NIKTO_CVE if is_cve else None,
            extra={
                "tool": self.name,
                "nikto_id": vuln.get("id"),
                "method": vuln.get("method"),
                "path": path,
                "references": references or None,
            },
        )
