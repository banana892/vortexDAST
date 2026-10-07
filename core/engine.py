"""
VortexDAST – core/engine.py
────────────────────────────────────────────────────────────────────────────
Programmatic scan engine — the CLI-independent core used by the REST API
(:mod:`core.api`) and any other embedding. It wires the existing building
blocks (Requester → Crawler → scanner modules → dedup → anomaly detection)
into one function that returns structured results instead of printing to a
terminal.

The CLI (``scanner.py``) keeps its rich progress UI; this module is the quiet,
embeddable path.

Anomaly Detection
-----------------
After all scanner modules finish, the engine collects per-endpoint response
features (body length, latency in ms, header count) and feeds them through
:class:`~core.anomaly.ResponseAnomalyDetector`.  Endpoints whose features are
statistical outliers are emitted as INFORMATIONAL "Response Anomaly" findings
for manual review.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.anomaly import ResponseAnomalyDetector
from core.crawler import Crawler
from core.reporter import Reporter
from core.requester import Requester
from modules.base import Confidence, Finding, Severity

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


def _collect_response_features(
    requester: Requester,
    urls: List[str],
) -> Tuple[List[Dict[str, float]], List[str]]:
    """
    Fetch each URL and capture per-response features for anomaly detection.

    Returns a tuple of (features, reachable_urls) guaranteed to have 1:1 alignment.
    """
    features: List[Dict[str, float]] = []
    valid_urls: List[str] = []
    for url in urls:
        t0 = time.monotonic()
        resp, err = requester.get(url)
        latency_ms = (time.monotonic() - t0) * 1000
        if err or resp is None:
            continue
        features.append({
            "body_length": float(len(resp.text or "")),
            "latency_ms": round(latency_ms, 2),
            "header_count": float(len(resp.headers)),
        })
        valid_urls.append(url)
    return features, valid_urls


def _anomaly_findings(
    features: List[Dict[str, float]],
    urls: List[str],
) -> List[Finding]:
    """Run the anomaly detector and convert outliers to Finding objects."""
    if len(features) < 5:
        # Not enough data to form a meaningful baseline.
        return []

    detector = ResponseAnomalyDetector()
    results = detector.detect(features)
    findings: List[Finding] = []
    for result in results:
        url = urls[result.index] if 0 <= result.index < len(urls) else "unknown"

        reason_text = ", ".join(
            f"{feat}: z={score}" for feat, score in result.reasons.items()
        )
        findings.append(Finding(
            title="Response Anomaly Detected",
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.TENTATIVE,
            url=url,
            evidence=reason_text,
            description=(
                f"This endpoint's response is a statistical outlier compared to the "
                f"scan baseline. Anomalous features: {reason_text}. "
                "This may indicate an unusual server-side behaviour worth manual review "
                "(e.g. timing side-channel, data leakage, hidden error state)."
            ),
            remediation=(
                "Investigate whether the anomalous response characteristics indicate a "
                "security issue (e.g. verbose error pages, timing differences leaking "
                "information, unusually large responses exposing internal data)."
            ),
            extra={
                "anomaly_reasons": result.reasons,
                "features": {
                    k: v for k, v in result.features.items()
                    if k != "_url"
                },
                "module": "anomaly_detection",
            },
        ))
    return findings


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
    enable_anomaly_detection: bool = True,
) -> ScanReport:
    """
    Run a full crawl + fuzz scan and return a :class:`ScanReport`.

    Parameters mirror the CLI's knobs. ``progress``, if given, is called with
    ``(phase, detail)`` updates ("crawl_done", "module_done", "anomaly_done",
    "complete") so a caller (e.g. the API's SSE stream) can report live
    progress.

    When ``enable_anomaly_detection`` is True (default), the engine re-fetches
    each endpoint after scanning and feeds the responses through the statistical
    anomaly detector, emitting INFORMATIONAL findings for outliers.

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
    endpoints_list: List[Any] = []
    try:
        crawler = Crawler(
            requester=requester,
            max_depth=max_depth,
            max_workers=threads,
            max_endpoints=max_endpoints,
        )
        crawl_result = crawler.crawl(seed_url=target, scope_config={})
        endpoints_list = crawl_result.endpoints
        if progress:
            progress("crawl_done", {"endpoints": len(endpoints_list)})

        for name in selected:
            module = registry[name](requester)
            for ep in endpoints_list:
                try:
                    findings.extend(module.run(ep))
                except Exception as exc:  # noqa: BLE001 — isolate per endpoint
                    logger.warning("module %s failed on %s: %s", name, ep.url, exc)
            if progress:
                progress("module_done", {"module": name, "total_findings": len(findings)})

        # ── Anomaly detection phase ──────────────────────────────────────
        if enable_anomaly_detection and endpoints_list:
            urls = [ep.url for ep in endpoints_list]
            try:
                features, valid_urls = _collect_response_features(requester, urls)
                anomaly_findings = _anomaly_findings(features, valid_urls)
                findings.extend(anomaly_findings)
                if progress:
                    progress("anomaly_done", {"anomalies": len(anomaly_findings)})
            except Exception as exc:  # noqa: BLE001
                logger.warning("anomaly detection failed: %s", exc)

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
            "endpoints_scanned": len(endpoints_list),
            "duration_s": round(duration, 2),
            "anomaly_detection": enable_anomaly_detection,
        },
    )
    if progress:
        progress("complete", {"total": len(findings)})
    return report
