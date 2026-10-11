"""
VortexDAST – adapters/testssl_adapter.py
────────────────────────────────────────────────────────────────────────────
Adapter for **testssl.sh** — deep TLS/SSL configuration analysis: protocol
versions, cipher suites, certificate chain/trust, and the named-vulnerability
checks (Heartbleed, POODLE, ROBOT, …). The last of the Phase E tier-3
adapters alongside nikto.

Like nikto, testssl.sh only ever writes JSON to a **file**
(``--jsonfile``/``-oj``), never to stdout, so this adapter overrides
:meth:`run` the same way: point it at a temp file, run it, read that file
back. Unlike nikto, testssl.sh carries its **own** severity per finding
(``OK``/``INFO``/``LOW``/``MEDIUM``/``HIGH``/``CRITICAL``/``WARN``) because
it's reporting directly-observed facts about the negotiated TLS handshake
and the certificate — not signature matches — so severity maps straight
across and confidence is uniformly CERTAIN.

Severity mapping
-----------------
``OK`` (passed — nothing wrong) and ``WARN`` (testssl's own tool-execution
caveat, e.g. "target is an IP not a hostname" — not a finding *about* the
target) are dropped. ``INFO`` is also dropped by default: the overwhelming
majority of testssl's ``INFO`` rows are plain configuration facts (cipher
list, cert serial number, session-ticket lifetime, …), not security notes —
including all of them would turn ~15 real findings into ~170 (measured
against a live test server), drowning the signal. ``LOW``/``MEDIUM``/
``HIGH``/``CRITICAL`` map straight across.

Licence note
------------
testssl.sh is GPL-licensed and invoked as a *separate program* (a bash
script, subprocess, never imported/sourced) — see IMPROVEMENTS.md §3.

Safety
------
The target reaches testssl.sh only as a single argv element through
:func:`core.orchestrator.run_command` (``shell=False``). Per-connection
timeouts (``--socket-timeout``/``--openssl-timeout``) are set so a single
unresponsive handshake can't hang the whole run; the usual hard subprocess
timeout is still the backstop. **Only scan targets you are authorised to
test** — testssl.sh makes many TLS connections per target.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional

from core.orchestrator import ScanContext, ToolAdapter, run_command
from modules.base import Confidence, Finding, Severity

logger = logging.getLogger(__name__)

#: testssl's own severity → ours. OK/WARN/INFO (and anything unrecognised)
#: are intentionally absent — see the module docstring.
_SEVERITY_MAP: Dict[str, Severity] = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}

#: Per-connection timeouts (seconds) so one unresponsive handshake can't
#: stall the whole run; the hard subprocess timeout is still the backstop.
_SOCKET_TIMEOUT_S = 10
_OPENSSL_TIMEOUT_S = 10


class TestsslAdapter(ToolAdapter):
    """Drive testssl.sh (via a temp JSON file) and map its findings into Findings."""

    name: str = "testssl"
    binary: str = "testssl.sh"
    description: str = (
        "Deep TLS/SSL analysis: protocols, cipher suites, certificate trust, "
        "and named vulnerabilities (Heartbleed, POODLE, ROBOT, …). Findings "
        "are directly-observed handshake/certificate facts, not signature "
        "matches. Optional external tool."
    )
    default_timeout: float = 300.0

    def __init__(self) -> None:
        self._output_path: str = ""
        #: Stashed by run() purely for parity with the other adapters —
        #: testssl's own records already carry ip/port, so it's unused in
        #: mapping, but kept for symmetry and future use.
        self._target: str = ""

    # ── ToolAdapter contract ──────────────────────────────────────────────

    def build_command(self, target: str, ctx: ScanContext) -> List[str]:
        """Argv for testssl.sh, writing JSON to :attr:`_output_path`."""
        return [
            self.binary,
            "--jsonfile",
            self._output_path or "testssl_output.json",
            "--quiet",
            "--warnings",
            "off",
            "--socket-timeout",
            str(_SOCKET_TIMEOUT_S),
            "--openssl-timeout",
            str(_OPENSSL_TIMEOUT_S),
            target,
        ]

    def parse(self, raw_output: str) -> List[Finding]:
        """Translate testssl.sh's flat JSON array into Findings."""
        if not raw_output or not raw_output.strip():
            return []
        try:
            records = json.loads(raw_output)
        except (ValueError, TypeError) as exc:
            logger.debug("testssl adapter: could not parse output: %s", exc)
            return []
        if not isinstance(records, list):
            return []

        findings: List[Finding] = []
        for record in records:
            finding = self._map_record(record)
            if finding is not None:
                findings.append(finding)
        return findings

    # ── Orchestration entry point (overrides the subprocess-only default) ──
    # testssl.sh, like nikto, has no stdout JSON mode — point it at a temp
    # file instead of trying to capture stdout.

    def run(self, target: str, ctx: ScanContext) -> List[Finding]:
        if not self.is_available():
            return self._fallback(target, ctx)

        self._target = target
        workdir = tempfile.mkdtemp(prefix="vortex-testssl-")
        self._output_path = os.path.join(workdir, "testssl.json")

        try:
            timeout = min(self.default_timeout, ctx.tool_timeout)
            argv = self.build_command(target, ctx)
            logger.debug("Running %s: %s", self.name, " ".join(argv))
            result = run_command(argv, timeout=timeout)

            if result.not_found:
                return self._fallback(target, ctx)
            if result.timed_out:
                logger.warning("Adapter 'testssl' timed out; checking for partial output.")
            elif result.returncode != 0:
                logger.warning(
                    "Adapter 'testssl' exited %d: %s",
                    result.returncode, result.stderr.strip()[:200],
                )

            raw = ""
            if os.path.isfile(self._output_path):
                with open(self._output_path, "r") as fh:
                    raw = fh.read()

            try:
                return self.parse(raw)
            except Exception as exc:  # pragma: no cover — defensive
                logger.error("Adapter 'testssl' failed to parse output: %s", exc)
                return []
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # ── Internal mapping ─────────────────────────────────────────────────

    def _map_record(self, record: Any) -> Optional[Finding]:
        if not isinstance(record, dict):
            return None

        severity = _SEVERITY_MAP.get(str(record.get("severity") or "").upper())
        if severity is None:
            return None  # OK / WARN / INFO / unrecognised — not a finding

        finding_text = (record.get("finding") or "").strip()
        check_id = record.get("id") or "testssl"
        ip = record.get("ip") or ""
        port = record.get("port") or ""
        host = ip.split("/")[0] if ip else ""
        url = f"{host}:{port}" if host and port else (host or self._target)

        cve = (record.get("cve") or "").strip()
        cwe = (record.get("cwe") or "").strip()

        evidence_parts = [f"id={check_id}"]
        if cve:
            evidence_parts.append(f"cve={cve}")
        if cwe:
            evidence_parts.append(f"cwe={cwe}")

        return Finding(
            title=f"TLS: {check_id} — {finding_text[:80]}",
            severity=severity,
            # A directly-observed protocol/cipher/certificate fact, not a
            # signature match — the strongest confidence tier.
            confidence=Confidence.CERTAIN,
            url=url,
            parameter=None,
            payload=None,
            evidence="; ".join(evidence_parts),
            description=finding_text or check_id,
            remediation=(
                "Review this TLS/SSL configuration finding and align it with "
                "current best practice (e.g. Mozilla's TLS configuration "
                "guidelines) for the server's required compatibility level."
            ),
            extra={
                "tool": self.name,
                "testssl_id": check_id,
                "cve": cve or None,
                "cwe": cwe or None,
                "ip": ip or None,
                "port": port or None,
            },
        )
