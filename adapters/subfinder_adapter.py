"""
VortexDAST – adapters/subfinder_adapter.py
────────────────────────────────────────────────────────────────────────────
Adapter for **subfinder** (ProjectDiscovery) — passive subdomain discovery.

subfinder queries public sources (certificate transparency logs, DNS
datasets, search engines, …) for hostnames under the target's registered
domain. It makes no requests to the target itself, so unlike every other
adapter here it is not "active probing" — but, like them, its output is only
useful once something consumes it: a discovered subdomain is just a name
until something checks whether it's alive. That consumer is httpx, via
``ScanContext.discovered_hosts`` — the same `host` list httpx already walks
its `open_ports` extras for, now also carrying subfinder's finds.

Invocation
----------
``subfinder -d <domain> -json -silent`` emits one JSON object per discovered
host on stdout (JSON-Lines): ``{"host": "...", "input": "...", "source": "..."}``.

Licence note
------------
subfinder is MIT-licensed and invoked as a *separate program* (subprocess),
so no licence obligation flows into VortexDAST.

Safety
------
The domain is derived from the scan target and passed as a single argv
element through :func:`core.orchestrator.run_command` (``shell=False``), so
a hostile target string cannot inject shell commands. Passive-only (public
sources, no packets to the target) — still, **only scan domains you are
authorised to test.**
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from core.orchestrator import ScanContext, ToolAdapter, parse_jsonl
from modules.base import Confidence, Finding, Severity


class SubfinderAdapter(ToolAdapter):
    """Drive ``subfinder`` and map its JSONL output into Findings."""

    name: str = "subfinder"
    binary: str = "subfinder"
    description: str = (
        "Passive subdomain discovery (ProjectDiscovery). Queries public "
        "sources for hostnames under the target's domain and feeds them "
        "forward for httpx to probe. Informational; no requests to the "
        "target itself. Optional external tool."
    )
    #: Passive source queries are network-bound but not target-bound; a
    #: generous timeout avoids cutting off a slow source mid-query.
    default_timeout: float = 300.0

    @staticmethod
    def _domain(target: str) -> str:
        """Extract the bare domain/host subfinder expects from a URL or host string."""
        return urlsplit(target).hostname or target.strip()

    def build_command(self, target: str, ctx: ScanContext) -> List[str]:
        """
        Build the subfinder argv.

        ``-json`` gives one JSON object per line; ``-silent`` keeps stdout
        pure JSONL; ``-disable-update-check`` keeps the run offline-friendly
        and deterministic for CI.
        """
        return [
            self.binary,
            "-d",
            self._domain(target),
            "-json",
            "-silent",
            "-disable-update-check",
        ]

    def parse(self, raw_output: str) -> List[Finding]:
        """Translate subfinder JSONL into informational :class:`Finding` objects."""
        findings: List[Finding] = []
        seen: set = set()
        for record in parse_jsonl(raw_output):
            finding = self._map_record(record, seen)
            if finding is not None:
                findings.append(finding)
        return findings

    def _map_record(self, record: Dict[str, Any], seen: set) -> Optional[Finding]:
        """Map one subfinder JSON object into a Finding (or ``None``)."""
        if not isinstance(record, dict):
            return None

        host = record.get("host")
        if not host or host in seen:
            return None
        seen.add(host)

        source = record.get("source") or ""

        return Finding(
            title=f"Discovered subdomain: {host}",
            # Purely informational recon — a name exists, nothing about it
            # has been probed yet.
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.CERTAIN,
            url=str(host),
            evidence=f"source={source}" if source else "",
            description=(
                "subfinder found this hostname under the target domain via "
                "a passive public source. Informational — provided for the "
                "attack-surface map and to seed downstream tools (httpx "
                "probes it for a live HTTP service)."
            ),
            remediation="",
            extra={
                "tool": self.name,
                "source": source or None,
                "input": record.get("input"),
                # Consumed by the orchestrator to chain discovered hosts
                # forward to httpx, same idiom as httpx's own
                # "http_service_url".
                "discovered_host": str(host),
            },
        )
