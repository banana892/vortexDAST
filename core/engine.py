"""
VortexDAST – core/engine.py
────────────────────────────────────────────────────────────────────────────
Programmatic scan engine — the CLI-independent core used by the REST API
(:mod:`core.api`) and any other embedding. It wires the existing building
blocks (Requester → Crawler → scanner modules → dedup) into one function that
returns structured results instead of printing to a terminal.

The CLI (``scanner.py``) keeps its rich progress UI; this module is the quiet,
embeddable path.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from core.crawler import Crawler
from core.reporter import Reporter
from core.requester import Requester
from modules.base import Finding

logger = logging.getLogger(__name__)

DEFAULT_MODULES = [
    "headers_audit",
    "xss_check",
    "sqli_check",
    "transport_check",
]

ProgressHook = Callable[[str, Dict[str, Any]], None]


@dataclass
class ScanReport:
    """Structured result of a programmatic scan."""

    target: str
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.metadata,
        }


def _resolve_module_registry() -> Dict[str, Any]:
    # Lazy import to avoid a core→scanner import cycle at module load time.
    from scanner import MODULE_REGISTRY  # noqa: PLC0415

    return MODULE_REGISTRY


def available_modules() -> List[str]:
    """Names of all registered scanner modules."""
    return sorted(_resolve_module_registry().keys())


def execute_scan(
    target: str,
    *,
    modules: Optional[List[str]] = None,
    max_depth: int = 2,
    max_endpoints: Optional[int] = 50,
    threads: int = 8,
    rate_limit_rps: float = 5.0,
    timeout: int = 10,
    verify_ssl: bool = True,
    progress: Optional[ProgressHook] = None,
) -> ScanReport:
    """
    Run a full crawl + fuzz scan and return a :class:`ScanReport`.

    Parameters mirror the CLI's knobs. ``progress``, if given, is called with
    ``(phase, detail)`` updates ("crawl_done", "module_done", "complete") so a
    caller (e.g. the API's SSE stream) can report live progress.

    Module exceptions are isolated per endpoint — one failure never aborts the
    scan. Never raises for a scan-logic problem; transport errors are already
    swallowed by :class:`~core.requester.Requester`.
    """
    registry = _resolve_module_registry()
    selected = modules or DEFAULT_MODULES
    unknown = [m for m in selected if m not in registry]
    if unknown:
        raise ValueError(f"unknown module(s): {', '.join(unknown)}")

    start = time.monotonic()
    requester = Requester(
        timeout=timeout,
        rate_limit_rps=rate_limit_rps,
        verify_ssl=verify_ssl,
        max_workers=threads,
    )

    findings: List[Finding] = []
    try:
        crawler = Crawler(
            requester=requester,
            max_depth=max_depth,
            max_workers=threads,
            max_endpoints=max_endpoints,
        )
        crawl_result = crawler.crawl(seed_url=target, scope_config={})
        endpoints = crawl_result.endpoints
        if progress:
            progress("crawl_done", {"endpoints": len(endpoints)})

        for name in selected:
            module = registry[name](requester)
            for ep in endpoints:
                try:
                    findings.extend(module.run(ep))
                except Exception as exc:  # noqa: BLE001 — isolate per endpoint
                    logger.warning("module %s failed on %s: %s", name, ep.url, exc)
            if progress:
                progress("module_done", {"module": name, "total_findings": len(findings)})
    finally:
        requester.close()

    findings = Reporter.deduplicate_findings(findings)
    duration = time.monotonic() - start

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    report = ScanReport(
        target=target,
        findings=findings,
        metadata={
            "total": len(findings),
            "by_severity": counts,
            "modules_run": selected,
            "endpoints_scanned": len(endpoints),
            "duration_s": round(duration, 2),
        },
    )
    if progress:
        progress("complete", {"total": len(findings)})
    return report
