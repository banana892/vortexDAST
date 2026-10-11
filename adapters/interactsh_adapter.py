"""
VortexDAST – adapters/interactsh_adapter.py
────────────────────────────────────────────────────────────────────────────
Adapter for **interactsh** (ProjectDiscovery) — an out-of-band (OAST) listener
that confirms *blind* vulnerabilities by detecting a server-side callback to
an attacker-controlled domain, per the IMPROVEMENTS.md Phase C design.

VortexDAST's own ``ssrf_check`` module is keyword-gated and reflection-based
(IMPROVEMENTS.md §5 item 6): it only flags SSRF when the response *echoes*
evidence of an internal fetch. Many real SSRFs are blind — the server fetches
the attacker's URL but never reflects anything back. This adapter closes that
gap for the one target URL it's given (the usual per-adapter scope; see
IMPROVEMENTS.md's "known follow-ups" on full data-chaining):

1. Start ``interactsh-client``, asking it to generate one unique correlation
   domain **per query parameter** on the target (``-n <param count>``) and
   write them to a local file (``-ps``/``-psf``) — so a later callback can be
   attributed back to the exact parameter that caused it.
2. For each parameter, issue one GET with that parameter's value replaced by
   ``http://<its own domain>/`` (every other parameter left untouched).
3. Give the server a short grace period to make any outbound call, then read
   whatever interactions ``interactsh-client`` logged (``-json -o <file>``) —
   a DNS lookup alone already proves the server tried to resolve our domain;
   a completed HTTP request proves it went further.
4. Map each distinct domain that fired into one Finding, attributed to its
   parameter, and tear the client down.

Target URLs with no query parameters have nothing to substitute into, so
:meth:`run` returns no findings for them without starting the client at all —
not a failure, just nothing to test.

shortcut: only query parameters are probed (no POST body/form fields, no
path segments); upgrade when the orchestrator passes adapters the full
crawled attack surface instead of one seed URL (Phase E data-chaining).

Licence note
------------
interactsh-client is MIT-licensed and invoked as a *separate program*
(subprocess), never imported — see IMPROVEMENTS.md §3.

Safety
------
Probe requests only ever set a parameter's value to our own interactsh
domain — never a path, header or destructive payload — and use the public,
anonymous interactsh server pool (no credentials, no cloud account). As with
every adapter, **only scan targets you are authorised to test**: an SSRF
finding here means the target server itself made an outbound request, which
is observable by the operator of whatever interactsh server was used.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from core.cvss import build_vector, calculate as cvss_calc
from core.orchestrator import ScanContext, ToolAdapter
from modules.base import Confidence, Finding, Severity

logger = logging.getLogger(__name__)

# Same CVSS modeling modules/ssrf_check.py uses for its own top (HIGH) tier:
# network-exploitable, no privileges, confirmed cross-boundary reach into
# whatever network the server can see (Scope: Changed).
_CVSS_VECTOR_SSRF_CONFIRMED = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"
)
_CVSS_SCORE_SSRF_CONFIRMED: float = cvss_calc(_CVSS_VECTOR_SSRF_CONFIRMED)  # 9.6

#: Hard cap on parameters probed per run — bounds request volume against the
#: target and payload count against the (shared, public) interactsh pool.
_MAX_PARAMS = 20
#: How long interactsh-client gets to register and write its payload file.
_STARTUP_TIMEOUT = 15.0
#: Grace period after sending probes, for an async server-side callback to
#: land and get polled/flushed by the client.
_SETTLE_SECONDS = 12.0
#: Per-probe HTTP request timeout — we don't need the target's response, only
#: that the request was delivered, so this stays short.
_PROBE_TIMEOUT = 10.0


class InteractshAdapter(ToolAdapter):
    """Drive interactsh-client to confirm blind SSRF via OOB callback."""

    name: str = "interactsh"
    binary: str = "interactsh-client"
    description: str = (
        "Out-of-band (OAST) interaction testing via interactsh-client. "
        "Substitutes a unique callback domain into each query parameter and "
        "confirms blind SSRF via a DNS/HTTP callback the reflection-based "
        "ssrf_check module can't see. Optional external tool."
    )
    #: Startup + probing + settle time, all told.
    default_timeout: float = 90.0
    #: Poll interval interactsh-client uses against the OAST server.
    poll_interval: int = 5

    def __init__(self) -> None:
        self._n: int = 1
        self._payload_file: str = ""
        self._interactions_file: str = ""
        #: unique-id (domain's leading label) → the parameter it was tried on.
        self._domain_to_param: Dict[str, str] = {}
        #: Stashed by run() so parse() can attach the scanned URL to each Finding.
        self._target: str = ""

    # ── ToolAdapter contract ──────────────────────────────────────────────

    def build_command(self, target: str, ctx: ScanContext) -> List[str]:
        """Argv to launch interactsh-client, writing payloads + interactions to files."""
        return [
            self.binary,
            "-json",
            "-ps",
            "-psf",
            self._payload_file or "interactsh_payload.txt",
            "-o",
            self._interactions_file or "interactsh_interactions.jsonl",
            "-n",
            str(self._n),
            "-pi",
            str(self.poll_interval),
            "-duc",
        ]

    def parse(self, raw_output: str) -> List[Finding]:
        """Group interaction JSONL by originating domain and map each to a Finding."""
        if not raw_output:
            return []

        by_label: Dict[str, List[Dict[str, Any]]] = {}
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record: Any = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(record, dict):
                continue
            label = record.get("unique-id") or record.get("full-id")
            if not label:
                continue
            by_label.setdefault(label, []).append(record)

        findings: List[Finding] = []
        for label, records in by_label.items():
            finding = self._map_interactions(label, records)
            if finding is not None:
                findings.append(finding)
        return findings

    # ── Orchestration entry point (overrides the subprocess-only default) ──

    def run(self, target: str, ctx: ScanContext) -> List[Finding]:
        if not self.is_available():
            return self._fallback(target, ctx)

        self._target = target
        params = self._extract_params(target)
        if not params:
            logger.info("interactsh: '%s' has no query parameters to probe.", target)
            return []
        params = params[:_MAX_PARAMS]

        deadline = time.monotonic() + min(self.default_timeout, ctx.tool_timeout)
        workdir = tempfile.mkdtemp(prefix="vortex-interactsh-")
        self._n = len(params)
        self._payload_file = os.path.join(workdir, "payloads.txt")
        self._interactions_file = os.path.join(workdir, "interactions.jsonl")

        try:
            try:
                proc = subprocess.Popen(
                    self.build_command(target, ctx),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except FileNotFoundError:
                return self._fallback(target, ctx)

            try:
                domains = self._wait_for_payloads(deadline)
                if not domains:
                    logger.warning("interactsh-client did not register in time.")
                    return []

                self._domain_to_param = {
                    domain.split(".", 1)[0]: param
                    for domain, param in zip(domains, params)
                }
                for domain, param in zip(domains, params):
                    self._send_probe(target, param, domain)

                time.sleep(max(0.0, min(_SETTLE_SECONDS, deadline - time.monotonic())))

                raw = ""
                if os.path.isfile(self._interactions_file):
                    with open(self._interactions_file, "r") as fh:
                        raw = fh.read()
                return self.parse(raw)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # ── Internal helpers ─────────────────────────────────────────────────

    @staticmethod
    def _extract_params(target: str) -> List[str]:
        """Distinct query-parameter names on ``target``, in order of first appearance."""
        query = urlsplit(target).query
        return list(dict.fromkeys(name for name, _ in parse_qsl(query, keep_blank_values=True)))

    @staticmethod
    def _send_probe(target: str, param: str, domain: str) -> None:
        """GET ``target`` with ``param`` set to our callback URL, other params untouched."""
        parts = urlsplit(target)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        probe_value = f"http://{domain}/"
        new_pairs = [(k, probe_value if k == param else v) for k, v in pairs]
        probe_url = urlunsplit(parts._replace(query=urlencode(new_pairs)))
        try:
            requests.get(probe_url, timeout=_PROBE_TIMEOUT)
        except requests.exceptions.RequestException as exc:
            logger.debug("interactsh probe request failed (ignored): %s", exc)

    def _wait_for_payloads(self, deadline: float) -> List[str]:
        """Poll the payload file until it has one line per requested domain."""
        startup_deadline = min(deadline, time.monotonic() + _STARTUP_TIMEOUT)
        while time.monotonic() < startup_deadline:
            if os.path.isfile(self._payload_file):
                lines = [
                    line.strip()
                    for line in open(self._payload_file).read().splitlines()
                    if line.strip()
                ]
                if len(lines) >= self._n:
                    return lines
            time.sleep(0.3)
        return []

    def _map_interactions(
        self, label: str, records: List[Dict[str, Any]]
    ) -> Optional[Finding]:
        param = self._domain_to_param.get(label, "?")
        protocols: List[str] = sorted(
            {p for r in records if isinstance(p := r.get("protocol"), str)}
        )
        remote_addrs: List[str] = sorted(
            {a for r in records if isinstance(a := r.get("remote-address"), str)}
        )

        # A completed HTTP round trip is stronger evidence than a bare DNS
        # lookup (which some resolvers/proxies can trigger incidentally).
        if "http" in protocols:
            confidence = Confidence.CERTAIN
        else:
            confidence = Confidence.FIRM

        description = (
            f"The server made an outbound {'/'.join(protocols)} request to an "
            f"attacker-controlled interactsh domain after parameter '{param}' "
            "was set to a URL pointing at it — confirming blind server-side "
            "request forgery that a reflection-based check cannot see."
        )

        return Finding(
            title=f"Blind SSRF confirmed via OOB callback: parameter '{param}'",
            severity=Severity.HIGH,
            confidence=confidence,
            url=self._target,
            parameter=param,
            payload=f"http://{label}.../",
            evidence=f"{len(records)} interaction(s) ({'/'.join(protocols)}) from {', '.join(remote_addrs)}",
            description=description,
            remediation=(
                "Validate and allow-list any server-side-fetched URL (scheme, "
                "host, no loopback/RFC1918/link-local/metadata addresses); "
                "never let user input choose an outbound destination directly."
            ),
            cvss_vector=_CVSS_VECTOR_SSRF_CONFIRMED,
            cvss_score=_CVSS_SCORE_SSRF_CONFIRMED,
            extra={
                "tool": self.name,
                "parameter": param,
                "domain_label": label,
                "protocols": protocols,
                "remote_addresses": remote_addrs,
                "interaction_count": len(records),
            },
        )
