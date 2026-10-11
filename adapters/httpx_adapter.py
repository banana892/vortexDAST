"""
VortexDAST – adapters/httpx_adapter.py
────────────────────────────────────────────────────────────────────────────
Adapter for **httpx** (ProjectDiscovery) — a fast HTTP prober.

httpx is the *glue* tool of the orchestration pipeline: it answers "which
host:port actually serve HTTP(S)?" and enriches each with status, page title,
web server and detected technologies. In the full chain it connects nmap's
open ports to the web scan and feeds live base URLs forward for nuclei.

Not to be confused with the Python ``httpx`` *library*: this adapter wraps the
ProjectDiscovery **CLI binary** of the same name, resolved on ``PATH``.

Invocation
----------
``httpx -u <target> -json -silent -disable-update-check`` emits one JSON object
per probed endpoint on stdout (JSON-Lines), reusing the shared
:func:`core.orchestrator.parse_jsonl` helper.

Licence note
------------
httpx (ProjectDiscovery) is MIT-licensed and invoked as a *separate program*,
so no licence obligation flows into VortexDAST.

Safety
------
The target is passed as a single argv element through
:func:`core.orchestrator.run_command` (``shell=False``); a hostile target
string cannot inject shell commands. **Only probe targets you are authorised
to test.**
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.orchestrator import (
    ScanContext,
    ToolAdapter,
    parse_jsonl,
    severity_from_label,
)
from modules.base import Confidence, Finding


class HttpxAdapter(ToolAdapter):
    """Drive ProjectDiscovery ``httpx`` and map its JSONL output into Findings."""

    name: str = "httpx"
    binary: str = "httpx"
    description: str = (
        "HTTP prober (ProjectDiscovery). Identifies live HTTP(S) services and "
        "their status, title, web server and technologies, and feeds live base "
        "URLs forward for other tools. Informational; the glue of the recon "
        "pipeline. Optional external tool."
    )
    #: Probing a single target is quick; keep the budget modest.
    default_timeout: float = 300.0

    def build_command(self, target: str, ctx: ScanContext) -> List[str]:
        """
        Build the httpx argv.

        ``-json`` gives one JSON object per line; ``-silent`` keeps stdout pure
        JSONL; ``-disable-update-check`` keeps the run offline-friendly and
        deterministic for CI.
        """
        return [
            self.binary,
            "-u",
            target,
            "-json",
            "-silent",
            "-disable-update-check",
        ]

    def parse(self, raw_output: str) -> List[Finding]:
        """Translate httpx JSONL into informational :class:`Finding` objects."""
        findings: List[Finding] = []
        for record in parse_jsonl(raw_output):
            finding = self._map_record(record)
            if finding is not None:
                findings.append(finding)
        return findings

    # ── Internal mapping ─────────────────────────────────────────────────────

    def _map_record(self, record: Dict[str, Any]) -> Optional[Finding]:
        """Map one httpx JSON object into a Finding (or ``None``)."""
        if not isinstance(record, dict):
            return None

        url = record.get("url") or record.get("input") or record.get("host") or ""
        if not url:
            return None

        status = record.get("status_code") or record.get("status-code")
        title = record.get("title") or ""
        webserver = record.get("webserver") or record.get("web-server") or ""
        tech = record.get("tech") or record.get("technologies") or []
        if isinstance(tech, str):
            tech = [tech]

        detail_bits: List[str] = []
        if status is not None:
            detail_bits.append(f"status={status}")
        if title:
            detail_bits.append(f"title={title!r}")
        if webserver:
            detail_bits.append(f"server={webserver}")
        if tech:
            detail_bits.append("tech=" + ",".join(str(t) for t in tech))
        evidence = "; ".join(detail_bits)

        return Finding(
            title=f"Live HTTP service: {url}",
            # Purely informational recon — httpx asserts liveness, not a flaw.
            severity=severity_from_label("info"),
            confidence=Confidence.CERTAIN,
            url=str(url),
            evidence=evidence,
            description=(
                "httpx confirmed a live HTTP(S) service here and fingerprinted "
                "its server/technologies. Informational — provided for the "
                "attack-surface map and to seed downstream tools."
            ),
            remediation="",
            extra={
                "tool": self.name,
                "status_code": status,
                "title": title or None,
                "webserver": webserver or None,
                "tech": list(tech) if tech else None,
                "scheme": record.get("scheme"),
                "host": record.get("host"),
                "port": record.get("port"),
                # Consumed by the orchestrator to chain live URLs forward.
                "http_service_url": str(url),
            },
        )
