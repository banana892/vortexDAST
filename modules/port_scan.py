"""
VortexDAST – modules/port_scan.py
────────────────────────────────────────────────────────────────────────────
Host-scoped network service discovery (TCP connect scan).

This module performs a lightweight TCP *connect* scan against the **single
host** resolved from the scan target URL.  It is intended for reconnaissance
during an *authorised* web-application assessment: it maps which network
services the same host exposes alongside the web application, so that an
exposed database, admin console, or legacy cleartext protocol is surfaced as
a finding rather than missed.

Scope & safety by design
-------------------------
* By default only the exact host already in the scan's scope is probed. A
  wider sweep requires the operator to pass an **explicit** CIDR range via
  ``--subnet``; there is no automatic host discovery, and the range is capped
  by ``--max-subnet-hosts`` so an over-broad block is rejected rather than
  scanned by accident.
* It is a TCP *connect* scan (full three-way handshake via the OS socket
  stack), not a raw/stealth SYN scan, so it behaves like any ordinary client
  connecting to a port.
* The module is **opt-in**: it is excluded from ``--modules all`` and only
  runs when the operator passes ``--port-scan`` / ``--ports`` / ``--subnet``.
* In single-host mode the scan runs once per host; in subnet mode the full
  host list is swept exactly once, regardless of how many endpoints crawled.
  The subnet sweep runs every host x port probe in one flat thread pool
  (``subnet_workers``) so timeouts on down hosts overlap instead of
  serialising host-by-host.
* Only scan hosts and ranges you are authorised to test.

Findings
--------
Each open port yields a finding. Ports carrying services that should normally
never face an untrusted network (databases, remote-access, unauthenticated
data stores, cleartext legacy protocols) are rated by the ``risk`` tag in
``payloads/common_ports.json``; plain web ports are informational.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.requester import Requester

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "payloads")
_PORTS_PATH = os.path.join(_PAYLOADS_DIR, "common_ports.json")

#: Map the payload ``risk`` tag → Finding severity.
_RISK_TO_SEVERITY: Dict[str, Severity] = {
    "high": Severity.MEDIUM,
    "medium": Severity.LOW,
    "low": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
}

#: Private / loopback / link-local prefixes — exposure matters less here, so we
#: soften severity by one step when the target is clearly not internet-facing.
_PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "169.254.", "::1")


def _sort_key(host: str):
    """Sort hosts numerically when they are IP addresses, else lexically."""
    try:
        import ipaddress  # noqa: PLC0415

        return (0, int(ipaddress.ip_address(host)))
    except ValueError:
        return (1, host)


class PortScanModule(BaseScannerModule):
    """Host-scoped TCP connect scan for exposed network services."""

    name: str = "port_scan"
    description: str = (
        "Opt-in TCP connect scan. Scans the target host by default, or an "
        "explicit CIDR range via --subnet. Discovers exposed network services "
        "(databases, admin consoles, remote-access, legacy cleartext "
        "protocols) and flags risky ones."
    )

    # ── Operator-tunable knobs (set by scanner.py from CLI flags) ──────────
    #: Explicit port list override. ``None`` → use payloads/common_ports.json.
    ports: Optional[List[int]] = None
    #: Explicit list of hosts/IPs to scan (e.g. an expanded CIDR range). When
    #: set, these hosts are scanned instead of the per-endpoint target host.
    #: ``None`` → derive the single host from each crawled endpoint's URL.
    subnet_hosts: Optional[List[str]] = None
    #: Per-port connection timeout, seconds.
    connect_timeout: float = 1.5
    #: Max concurrent socket probes for a single host.
    max_port_workers: int = 20
    #: Max concurrent socket probes for a subnet sweep (host×port pairs run in
    #: one flat pool; higher than max_port_workers since sweeps are I/O-bound
    #: and many hosts are typically down).
    subnet_workers: int = 100
    #: Read up to this many bytes for a best-effort service banner.
    banner_bytes: int = 64

    def __init__(self, requester: Requester) -> None:
        super().__init__(requester)
        self._scanned_hosts: set[str] = set()
        self._subnet_done: bool = False
        self._lock = threading.Lock()
        self._catalog = self._load_catalog()

    # ── Payload loading ────────────────────────────────────────────────────

    def _load_catalog(self) -> Dict[int, Dict[str, str]]:
        """Load the port→metadata catalog keyed by port number."""
        try:
            with open(_PORTS_PATH, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            logger.warning("port_scan: could not load %s: %s", _PORTS_PATH, exc)
            return {}
        catalog: Dict[int, Dict[str, str]] = {}
        for entry in data.get("ports", []):
            try:
                catalog[int(entry["port"])] = {
                    "service": entry.get("service", "unknown"),
                    "risk": entry.get("risk", "info"),
                    "note": entry.get("note", ""),
                }
            except (KeyError, ValueError, TypeError):
                continue
        return catalog

    def _target_ports(self) -> List[int]:
        """Resolve the port list: explicit override, else the full catalog."""
        if self.ports:
            return sorted(set(self.ports))
        return sorted(self._catalog.keys())

    # ── Entry point ──────────────────────────────────────────────────────

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        ports = self._target_ports()
        if not ports:
            logger.warning("port_scan: no ports to scan (empty catalog/override).")
            return []

        # ── Subnet mode: scan the explicit host list once, in full. ────────
        if self.subnet_hosts:
            with self._lock:
                if self._subnet_done:
                    return []
                self._subnet_done = True
            logger.info(
                "port_scan: subnet sweep — %d host(s) x %d port(s)",
                len(self.subnet_hosts), len(ports),
            )
            open_hits = self._scan_many(self.subnet_hosts, ports)
            return [
                self._finding_for(host, port, banner)
                for host, port, banner in open_hits
            ]

        # ── Single-host mode: scan the endpoint's host once. ───────────────
        host = urlsplit(endpoint.url).hostname
        if not host:
            return []
        with self._lock:
            if host in self._scanned_hosts:
                return []
            self._scanned_hosts.add(host)

        logger.info("port_scan: scanning %d ports on %s", len(ports), host)
        open_ports = self._scan_host(host, ports)
        return [self._finding_for(host, port, banner) for port, banner in open_ports]

    # ── Scanning ───────────────────────────────────────────────────────────

    def _scan_many(
        self, hosts: List[str], ports: List[int]
    ) -> List[Tuple[str, int, str]]:
        """
        Scan ``hosts`` × ``ports`` as one flat, parallel work set.

        Every ``(host, port)`` probe is submitted to a single pool so that
        connection timeouts on down hosts overlap instead of serialising
        host-by-host — the key win when sweeping a mostly-dead range. Results
        are returned sorted by ``(host, port)`` for deterministic output.
        """
        pairs = [(host, port) for host in hosts for port in ports]
        if not pairs:
            return []
        workers = max(1, min(self.subnet_workers, len(pairs)))
        results: List[Tuple[str, int, str]] = []
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="vdast-sweep"
        ) as pool:
            future_map = {
                pool.submit(self._probe_port, host, port): (host, port)
                for host, port in pairs
            }
            for future in as_completed(future_map):
                host, port = future_map[future]
                try:
                    is_open, banner = future.result()
                except Exception as exc:  # noqa: BLE001 — never abort the sweep
                    logger.debug("port_scan: probe %s:%d errored: %s", host, port, exc)
                    continue
                if is_open:
                    results.append((host, port, banner))
        return sorted(results, key=lambda t: (_sort_key(t[0]), t[1]))

    def _scan_host(self, host: str, ports: List[int]) -> List[Tuple[int, str]]:
        """Return a sorted list of ``(port, banner)`` for every open port."""
        results: List[Tuple[int, str]] = []
        workers = max(1, min(self.max_port_workers, len(ports)))
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="vdast-port"
        ) as pool:
            future_map = {
                pool.submit(self._probe_port, host, port): port for port in ports
            }
            for future in as_completed(future_map):
                port = future_map[future]
                try:
                    is_open, banner = future.result()
                except Exception as exc:  # noqa: BLE001 — never abort the scan
                    logger.debug("port_scan: probe %s:%d errored: %s", host, port, exc)
                    continue
                if is_open:
                    results.append((port, banner))
        return sorted(results, key=lambda t: t[0])

    def _probe_port(self, host: str, port: int) -> Tuple[bool, str]:
        """
        TCP connect probe for one port.

        Returns ``(is_open, banner)``. A best-effort banner is read only if the
        service volunteers one quickly; we never send protocol-specific data.
        """
        try:
            with socket.create_connection((host, port), timeout=self.connect_timeout) as sock:
                banner = self._grab_banner(sock)
                return True, banner
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False, ""

    def _grab_banner(self, sock: socket.socket) -> str:
        """Read a short, passively-offered banner (e.g. SSH/FTP/SMTP greeting)."""
        try:
            sock.settimeout(min(self.connect_timeout, 1.0))
            raw = sock.recv(self.banner_bytes)
        except (socket.timeout, OSError):
            return ""
        text = raw.decode("latin-1", errors="replace").strip()
        # Keep only the first line, collapse control chars.
        first_line = text.splitlines()[0] if text else ""
        return "".join(ch for ch in first_line if ch.isprintable())[: self.banner_bytes]

    # ── Finding construction ────────────────────────────────────────────────

    def _finding_for(self, host: str, port: int, banner: str) -> Finding:
        meta = self._catalog.get(port, {"service": "unknown", "risk": "info", "note": ""})
        service = meta["service"]
        risk = meta["risk"]
        note = meta["note"]

        severity = _RISK_TO_SEVERITY.get(risk, Severity.INFORMATIONAL)
        # Soften one step for clearly non-internet-facing hosts.
        if host.startswith(_PRIVATE_PREFIXES) and severity == Severity.MEDIUM:
            severity = Severity.LOW

        evidence = f"TCP {host}:{port} open"
        if banner:
            evidence += f" — banner: {banner!r}"

        if risk in ("high", "medium") and severity != Severity.INFORMATIONAL:
            title = f"Exposed Service: {service} (tcp/{port})"
            description = (
                f"The host exposes {service} on TCP port {port}. {note} "
                "Exposing this service to an untrusted network broadens the "
                "attack surface well beyond the web application itself."
            )
            remediation = (
                f"Confirm {service} on port {port} must be reachable from this "
                "network. If not, bind it to localhost or restrict it with a "
                "host/network firewall or security group. Require authentication "
                "and keep the service patched."
            )
        else:
            title = f"Open Port: {service} (tcp/{port})"
            description = (
                f"The host has TCP port {port} ({service}) open. {note}".strip()
            )
            remediation = (
                "Verify this port is intended to be reachable. Close or "
                "firewall any port that does not need to be exposed."
            )

        return Finding(
            title=title,
            severity=severity,
            confidence=Confidence.CERTAIN,
            url=f"{host}:{port}",
            parameter=None,
            payload=None,
            evidence=evidence,
            description=description,
            remediation=remediation,
            extra={
                "module": self.name,
                "host": host,
                "port": port,
                "service": service,
                "risk": risk,
                "banner": banner,
            },
        )
