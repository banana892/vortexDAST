"""
VortexDAST – adapters/nmap_adapter.py
────────────────────────────────────────────────────────────────────────────
Adapter for **nmap** — the de-facto network mapper / port & service scanner.

nmap makes the *reconnaissance* half of VortexDAST real: it discovers which
TCP services a host exposes alongside the web application, with far better
service/version fingerprinting than a plain socket connect scan. When nmap is
**not** installed, this adapter degrades to the built-in
:class:`~modules.port_scan.PortScanModule` so a scan never *requires* nmap —
exactly the detection + fallback guarantee from ``IMPROVEMENTS.md`` §2.1.

Invocation
----------
``nmap -Pn -T4 -oX - <host>`` runs a connect/SYN scan and writes its result as
XML to stdout (``-oX -``). The XML ``<port>`` elements carry state, protocol,
service name and (when ``-sV`` is in play) product/version, which map cleanly
onto a VortexDAST :class:`Finding`.

Licence note
------------
nmap is GPL-licensed and invoked as a *separate program* (subprocess), so no
licence obligation flows into VortexDAST — we never import its code.

Safety
------
The host is derived from the scan target and passed as a single argv element
through :func:`core.orchestrator.run_command` (``shell=False``), so a hostile
target string cannot inject shell commands. nmap performs active network
probing — **only scan hosts you are authorised to test.**
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, List, Optional, cast
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from core.orchestrator import ScanContext, ToolAdapter
from modules.base import Confidence, Finding, Severity

if TYPE_CHECKING:
    from core.requester import Requester

logger = logging.getLogger(__name__)


#: Services that should rarely face an untrusted network. An open port running
#: one of these is surfaced as a MEDIUM (vs INFORMATIONAL for ordinary ports),
#: mirroring the risk weighting in ``modules/port_scan.py``.
_RISKY_SERVICES = frozenset(
    {
        "ms-sql-s", "mysql", "postgresql", "oracle", "mongodb", "redis",
        "memcached", "elasticsearch", "couchdb", "cassandra",
        "ssh", "telnet", "rdp", "ms-wbt-server", "vnc", "rlogin",
        "ftp", "tftp", "smb", "microsoft-ds", "netbios-ssn", "rpcbind",
        "ldap", "smtp", "snmp", "docker", "kubernetes",
    }
)


class NmapAdapter(ToolAdapter):
    """Drive ``nmap`` and map its XML output into Findings."""

    name: str = "nmap"
    binary: str = "nmap"
    description: str = (
        "Network port/service/version scanner (nmap). Discovers exposed TCP "
        "services on the target host and flags risky ones. Falls back to the "
        "built-in TCP connect scan when nmap is not installed. Optional "
        "external tool; active network probing — authorised targets only."
    )
    #: A default-port connect scan is quick; version detection can be slower.
    default_timeout: float = 600.0

    # ── Command building ─────────────────────────────────────────────────────

    @staticmethod
    def _host(target: str) -> str:
        """Extract the bare hostname/IP nmap expects from a URL or host string."""
        return urlsplit(target).hostname or target.strip()

    def build_command(self, target: str, ctx: ScanContext) -> List[str]:
        """
        Build the nmap argv.

        ``-Pn`` skips host discovery (treat the host as up — it is already in
        scope), ``-T4`` picks a brisk timing template, and ``-oX -`` streams
        the structured XML report to stdout for :meth:`parse`.
        """
        return [self.binary, "-Pn", "-T4", "-oX", "-", self._host(target)]

    # ── Parsing ──────────────────────────────────────────────────────────────

    def parse(self, raw_output: str) -> List[Finding]:
        """Translate nmap XML into :class:`Finding` objects (one per open port)."""
        findings: List[Finding] = []
        if not raw_output.strip():
            return findings

        try:
            # nmap XML comes from a tool *we* spawned (not the target), and
            # ElementTree does not resolve external entities, so this parse is
            # not an untrusted-XML sink.
            root = ET.fromstring(raw_output)  # noqa: S314
        except ET.ParseError as exc:
            logger.debug("nmap: could not parse XML output: %s", exc)
            return findings

        for host_el in root.findall("host"):
            addr = self._host_address(host_el)
            for port_el in host_el.findall("./ports/port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                finding = self._map_port(addr, port_el)
                if finding is not None:
                    findings.append(finding)
        return findings

    @staticmethod
    def _host_address(host_el: ET.Element) -> str:
        """Pick the most useful address for a ``<host>`` (IPv4/6 over MAC)."""
        addr = ""
        for addr_el in host_el.findall("address"):
            kind = addr_el.get("addrtype", "")
            if kind in ("ipv4", "ipv6"):
                return addr_el.get("addr", "")
            addr = addr_el.get("addr", addr)
        return addr

    def _map_port(self, host: str, port_el: ET.Element) -> Optional[Finding]:
        """Map a single open ``<port>`` element into a Finding."""
        portid = port_el.get("portid")
        if not portid:
            return None
        proto = port_el.get("protocol", "tcp")

        service_el = port_el.find("service")
        service = "unknown"
        product_bits: List[str] = []
        if service_el is not None:
            service = service_el.get("name") or "unknown"
            for attr in ("product", "version", "extrainfo"):
                val = service_el.get(attr)
                if val:
                    product_bits.append(val)
        product = " ".join(product_bits)

        risky = service.lower() in _RISKY_SERVICES
        severity = Severity.MEDIUM if risky else Severity.INFORMATIONAL

        evidence = f"{proto}/{portid} open — service: {service}"
        if product:
            evidence += f" ({product})"

        if risky:
            title = f"Exposed Service: {service} ({proto}/{portid})"
            description = (
                f"nmap reports {service} open on {proto} port {portid} of "
                f"{host}. Exposing this service to an untrusted network "
                "broadens the attack surface beyond the web application."
            )
            remediation = (
                f"Confirm {service} on port {portid} must be reachable from "
                "this network. If not, bind it to localhost or restrict it "
                "with a firewall/security group, require authentication, and "
                "keep it patched."
            )
        else:
            title = f"Open Port: {service} ({proto}/{portid})"
            description = (
                f"nmap reports {proto} port {portid} ({service}) open on {host}."
            )
            remediation = (
                "Verify this port is intended to be reachable. Close or "
                "firewall any port that does not need to be exposed."
            )

        return Finding(
            title=title,
            severity=severity,
            confidence=Confidence.CERTAIN,
            url=f"{host}:{portid}",
            evidence=evidence,
            description=description,
            remediation=remediation,
            extra={
                "tool": self.name,
                "host": host,
                "port": int(portid) if portid.isdigit() else portid,
                "protocol": proto,
                "service": service,
                "product": product or None,
            },
        )

    # ── Fallback ───────────────────────────────────────────────────────────────

    def _fallback(self, target: str, ctx: ScanContext) -> List[Finding]:
        """
        Degrade to the built-in TCP connect scan when nmap is absent.

        Honours the detection+fallback guarantee: the recon half still runs,
        just with the socket-based :class:`~modules.port_scan.PortScanModule`
        instead of nmap's richer fingerprinting. The port scanner never uses
        the HTTP requester for its socket probes, so a missing one is fine.
        """
        logger.info("nmap not installed — falling back to the built-in TCP port scan.")
        try:
            from core.crawler import CrawledEndpoint  # noqa: PLC0415 — deferred
            from modules.port_scan import PortScanModule  # noqa: PLC0415 — deferred
        except ImportError as exc:  # pragma: no cover — defensive
            logger.debug("nmap fallback unavailable: %s", exc)
            return []

        # PortScanModule only stores the requester (its probes are raw
        # sockets), so running without one — e.g. a direct adapter call — is safe.
        requester = cast("Requester", ctx.extra.get("requester"))
        module = PortScanModule(requester)
        endpoint = CrawledEndpoint(url=target, status_code=0, depth=0)
        findings = module.run(endpoint)
        # Tag findings with the adapter name so reports show the orchestration
        # path that produced them, while keeping port_scan's own metadata.
        for finding in findings:
            finding.extra.setdefault("tool", self.name)
            finding.extra["via"] = "port_scan_fallback"
        return findings
