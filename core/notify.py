"""
VortexDAST – core/notify.py
Post a scan summary to a webhook (generic JSON or Slack incoming webhook).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from typing import Any, Dict, List, Optional, Tuple, Union
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


def _private_webhooks_allowed() -> bool:
    """Whether posting to internal/non-public addresses is explicitly opted in."""
    return (os.environ.get("VORTEX_ALLOW_PRIVATE_WEBHOOK") or "").strip().lower() in {
        "1", "true", "yes", "on",
    }


_IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def _is_blocked_ip(ip: _IPAddress) -> bool:
    """True if ``ip`` is an internal / non-routable address a webhook must not reach."""
    # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254) so the embedded v4
    # address is judged on its own merits, not as a "global" v6 address.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _webhook_target_is_safe(url: str) -> Tuple[bool, str]:
    """
    Resolve ``url``'s host and reject it if any resolved address is internal.

    Guards against SSRF: a caller-supplied webhook/callback URL must not be used
    to make the scanner POST to loopback, RFC1918, link-local (incl. the cloud
    metadata endpoint 169.254.169.254), multicast or otherwise non-public
    addresses. Fails closed on an unresolvable host.
    """
    host = urlsplit(url).hostname
    if not host:
        return False, "no host in URL"
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, "host did not resolve"

    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]  # drop any IPv6 zone id
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False, "host resolved to an unparseable address"
        if _is_blocked_ip(ip):
            return False, "host resolves to a non-public address"
    return True, ""


def send_webhook(
    url: str,
    payload: Dict[str, Any],
    *,
    allow_private: Optional[bool] = None,
) -> bool:
    """POST the payload; never raises. Logs only the host since webhook URLs embed secrets.

    By default the destination is blocked when it resolves to an internal /
    non-public address (SSRF guard). Pass ``allow_private=True`` (or set
    ``VORTEX_ALLOW_PRIVATE_WEBHOOK=1``) to permit internal targets for local
    receivers you control. Redirects are never followed, so a cleared external
    host cannot bounce the POST to an internal one.
    """
    host = urlsplit(url).netloc or "webhook"
    if allow_private is None:
        allow_private = _private_webhooks_allowed()
    if not allow_private:
        safe, reason = _webhook_target_is_safe(url)
        if not safe:
            logger.warning(
                "Webhook to %s blocked: %s. Set VORTEX_ALLOW_PRIVATE_WEBHOOK=1 "
                "to allow internal targets.",
                host, reason,
            )
            return False
    try:
        resp = requests.post(url, json=payload, timeout=_TIMEOUT_S, allow_redirects=False)
    except requests.RequestException as exc:
        logger.warning("Webhook to %s failed: %s", host, type(exc).__name__)
        return False
    if resp.status_code >= 400:
        logger.warning("Webhook to %s returned HTTP %d", host, resp.status_code)
        return False
    logger.info("Scan summary sent to webhook (%s).", host)
    return True
