"""
VortexDAST – core/notify.py
Post a scan summary to a webhook (generic JSON or Slack incoming webhook).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import requests

from modules.base import Finding

logger = logging.getLogger(__name__)

WEBHOOK_FORMATS = ("json", "slack")
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
_MAX_LISTED = 20
_TIMEOUT_S = 10


def build_payload(
    findings: List[Finding],
    target: str,
    fmt: str,
    exit_code: int,
    scan_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Summary without evidence/payloads — those can contain leaked secrets."""
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    ranked = sorted(findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.value))
    listed = [
        {
            "title": f.title,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "url": f.url,
        }
        for f in ranked[:_MAX_LISTED]
    ]

    count_line = ", ".join(f"{counts[s]} {s}" for s in _SEVERITY_ORDER if counts[s]) or "no findings"
    text = f"VortexDAST scan of {target}: {count_line}."

    if fmt == "slack":
        lines = [f"*VortexDAST scan of {target}* — {count_line}"]
        for item in listed:
            if item["severity"] in ("critical", "high", "medium"):
                lines.append(f"• [{item['severity'].upper()}] {item['title']} — {item['url']}")
        if len(findings) > _MAX_LISTED:
            lines.append(f"_…and {len(findings) - _MAX_LISTED} more in the full report._")
        return {"text": "\n".join(lines)}

    return {
        "text": text,
        "target": target,
        "exit_code": exit_code,
        "summary": {"total": len(findings), "by_severity": counts},
        "findings": listed,
        "truncated": len(findings) > _MAX_LISTED,
        "scan_metadata": {k: str(v) for k, v in (scan_meta or {}).items()},
    }


def send_webhook(url: str, payload: Dict[str, Any]) -> bool:
    """POST the payload; never raises. Logs only the host since webhook URLs embed secrets."""
    host = urlsplit(url).netloc or "webhook"
    try:
        resp = requests.post(url, json=payload, timeout=_TIMEOUT_S)
    except requests.RequestException as exc:
        logger.warning("Webhook to %s failed: %s", host, type(exc).__name__)
        return False
    if resp.status_code >= 400:
        logger.warning("Webhook to %s returned HTTP %d", host, resp.status_code)
        return False
    logger.info("Scan summary sent to webhook (%s).", host)
    return True
