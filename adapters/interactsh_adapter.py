"""
VortexDAST – adapters/interactsh_adapter.py
────────────────────────────────────────────────────────────────────────────
Adapter for **interactsh** (ProjectDiscovery) — an out-of-band (OAST) listener
that confirms *blind* vulnerabilities by detecting a server-side callback to
an attacker-controlled domain, per the IMPROVEMENTS.md Phase C design.

VortexDAST's own heuristic checks are reflection-based: ``ssrf_check`` only
flags SSRF when the response *echoes* evidence of an internal fetch, and
there is no blind-RCE/blind-SQLi detector at all (IMPROVEMENTS.md §5 items 4
and 6). Many real vulnerabilities are blind — the server acts on the
attacker's payload but never reflects anything back. This adapter confirms
three vulnerability classes that way, for the one target URL it's given (the
usual per-adapter scope; see IMPROVEMENTS.md's "known follow-ups" on full
data-chaining):

- **SSRF** — parameter value set to our own URL.
- **OS command injection (RCE)** — parameter value set to a shell
  metacharacter payload invoking ``nslookup`` against our domain.
- **Blind SQL injection** — parameter value set to a DBMS-specific
  out-of-band payload (MSSQL ``xp_dirtree``, Oracle ``UTL_INADDR``) that
  forces a DNS lookup if the query is actually executed.

Mechanism, generalised across all three:

1. Start ``interactsh-client``, asking it to generate one unique correlation
   domain **per (query parameter, payload) combination** on the target
   (``-n <count>``) and write them to a local file (``-ps``/``-psf``) — so a
   later callback can be attributed back to the exact parameter *and*
   vulnerability class that caused it.
2. For each combination, issue one GET with that parameter's value replaced
   by the corresponding payload rendered against its own domain (every other
   parameter left untouched).
3. Give the server a short grace period to make any outbound call, then read
   whatever interactions ``interactsh-client`` logged (``-json -o <file>``) —
   a DNS lookup alone already proves the server tried to resolve our domain;
   a completed HTTP request proves it went further.
4. Map each distinct domain that fired into one Finding, attributed to its
   parameter and vulnerability class, and tear the client down.

Target URLs with no query parameters have nothing to substitute into, so
:meth:`run` returns no findings for them without starting the client at all —
not a failure, just nothing to test.

shortcut: only query parameters are probed (no POST body/form fields, no
path segments, no XML body for XXE); upgrade when the orchestrator passes
adapters the full crawled attack surface instead of one seed URL (Phase E
data-chaining). XXE in particular needs a request body, not a query-param
substitution, so it isn't covered by this mechanism at all yet.

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
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple
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

# Confirmed blind OS command injection: the server actually ran our
# payload, reaching the underlying host — Scope:Changed, full C/I/A.
# AV:N / AC:L / PR:N / UI:N / S:C / C:H / I:H / A:H → 10.0 (CRITICAL)
_CVSS_VECTOR_RCE_CONFIRMED = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"
)
_CVSS_SCORE_RCE_CONFIRMED: float = cvss_calc(_CVSS_VECTOR_RCE_CONFIRMED)  # 10.0

# Confirmed blind SQLi via OOB DNS exfiltration: the DBMS actually executed
# our injected query (higher confidence than sqli_check's heuristic blind
# detector), full read/write, no availability impact from a DNS lookup alone.
# AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:N → 9.1 (CRITICAL)
_CVSS_VECTOR_SQLI_OOB_CONFIRMED = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"
)
_CVSS_SCORE_SQLI_OOB_CONFIRMED: float = cvss_calc(_CVSS_VECTOR_SQLI_OOB_CONFIRMED)  # 9.1


class _ProbeSpec(NamedTuple):
    """One payload family: which vuln class it confirms, how to render it."""

    kind: str
    render: Callable[[str], str]


#: Payload per vulnerability class, keyed by the domain interactsh-client
#: generates for that probe. Two RCE variants (statement-separator and
#: command-substitution) cover the two most common shell-injection shapes;
#: ``nslookup`` is used (not curl/wget) because it's present on both Windows
#: and Linux and only needs DNS resolution, not an HTTP client binary.
_PROBE_SPECS: List[_ProbeSpec] = [
    _ProbeSpec("ssrf", lambda d: f"http://{d}/"),
    _ProbeSpec("rce", lambda d: f"; nslookup {d} #"),
    _ProbeSpec("rce", lambda d: f"`nslookup {d}`"),
    _ProbeSpec("sqli_mssql", lambda d: f"';EXEC master..xp_dirtree '\\\\{d}\\test';--"),
    _ProbeSpec(
        "sqli_oracle",
        lambda d: f"' UNION SELECT UTL_INADDR.get_host_address('{d}') FROM dual--",
    ),
]

#: Per-vulnerability-class finding content. ``description``/``payload_preview``
#: are ``str.format`` templates filled in with the actual protocol/param/domain.
_VULN_META: Dict[str, Dict[str, Any]] = {
    "ssrf": dict(
        title_label="Blind SSRF",
        severity=Severity.HIGH,
        cvss_vector=_CVSS_VECTOR_SSRF_CONFIRMED,
        cvss_score=_CVSS_SCORE_SSRF_CONFIRMED,
        payload_preview="http://{domain}/",
        description=(
            "The server made an outbound {protocols} request to an "
            "attacker-controlled interactsh domain after parameter '{param}' "
            "was set to a URL pointing at it — confirming blind server-side "
            "request forgery that a reflection-based check cannot see."
        ),
        remediation=(
            "Validate and allow-list any server-side-fetched URL (scheme, "
            "host, no loopback/RFC1918/link-local/metadata addresses); never "
            "let user input choose an outbound destination directly."
        ),
    ),
    "rce": dict(
        title_label="Blind OS command injection",
        severity=Severity.CRITICAL,
        cvss_vector=_CVSS_VECTOR_RCE_CONFIRMED,
        cvss_score=_CVSS_SCORE_RCE_CONFIRMED,
        payload_preview="; nslookup {domain} #",
        description=(
            "The server made an outbound {protocols} request to an "
            "attacker-controlled interactsh domain after parameter '{param}' "
            "was set to a shell command-injection payload invoking "
            "nslookup — confirming blind remote code execution."
        ),
        remediation=(
            "Never pass user input to a shell or exec call; use an argv-list "
            "subprocess API (never shell=True on interpolated input) and "
            "validate against an allow-list of expected values."
        ),
    ),
    "sqli_mssql": dict(
        title_label="Blind SQL injection (MSSQL xp_dirtree)",
        severity=Severity.CRITICAL,
        cvss_vector=_CVSS_VECTOR_SQLI_OOB_CONFIRMED,
        cvss_score=_CVSS_SCORE_SQLI_OOB_CONFIRMED,
        payload_preview="';EXEC master..xp_dirtree '\\\\{domain}\\test';--",
        description=(
            "The database server made an outbound {protocols} request to an "
            "attacker-controlled interactsh domain after parameter '{param}' "
            "was set to a stacked-query xp_dirtree UNC-path payload — "
            "confirming blind SQL injection against a Microsoft SQL Server "
            "backend."
        ),
        remediation=(
            "Use parameterized queries/prepared statements for every SQL "
            "statement that incorporates user input; never build SQL via "
            "string concatenation."
        ),
    ),
    "sqli_oracle": dict(
        title_label="Blind SQL injection (Oracle UTL_INADDR)",
        severity=Severity.CRITICAL,
        cvss_vector=_CVSS_VECTOR_SQLI_OOB_CONFIRMED,
        cvss_score=_CVSS_SCORE_SQLI_OOB_CONFIRMED,
        payload_preview="' UNION SELECT UTL_INADDR.get_host_address('{domain}') FROM dual--",
        description=(
            "The database server made an outbound {protocols} request to an "
            "attacker-controlled interactsh domain after parameter '{param}' "
            "was set to a UNION-based UTL_INADDR.get_host_address payload — "
            "confirming blind SQL injection against an Oracle backend."
        ),
        remediation=(
            "Use parameterized queries/prepared statements for every SQL "
            "statement that incorporates user input; never build SQL via "
            "string concatenation."
        ),
    ),
}

#: Hard cap on parameters probed per run — bounds request volume against the
#: target and payload count against the (shared, public) interactsh pool.
_MAX_PARAMS = 20
#: Hard cap on total probes (params × payload specs) per run, for the same
#: reason — with 5 specs, 20 params would mean 100 requests/domains.
_MAX_PROBES = 60
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
        "Substitutes a unique callback domain + payload into each query "
        "parameter and confirms blind SSRF, OS command injection and SQL "
        "injection (MSSQL/Oracle) via a DNS/HTTP callback that reflection-"
        "based checks can't see. Optional external tool."
    )
    #: Startup + probing + settle time, all told.
    default_timeout: float = 90.0
    #: Poll interval interactsh-client uses against the OAST server.
    poll_interval: int = 5

    def __init__(self) -> None:
        self._n: int = 1
        self._payload_file: str = ""
        self._interactions_file: str = ""
        #: unique-id (domain's leading label) → (parameter, vuln kind) it was tried on.
        self._domain_to_combo: Dict[str, Tuple[str, str]] = {}
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
        # Bound total probes (params × payload specs) to _MAX_PROBES, then
        # apply the per-param cap on whatever's left.
        max_params_for_budget = max(1, _MAX_PROBES // len(_PROBE_SPECS))
        params = params[: min(_MAX_PARAMS, max_params_for_budget)]
        combos: List[Tuple[str, _ProbeSpec]] = [
            (param, spec) for param in params for spec in _PROBE_SPECS
        ]

        deadline = time.monotonic() + min(self.default_timeout, ctx.tool_timeout)
        workdir = tempfile.mkdtemp(prefix="vortex-interactsh-")
        self._n = len(combos)
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

                self._domain_to_combo = {}
                for (param, spec), domain in zip(combos, domains):
                    label = domain.split(".", 1)[0]
                    self._domain_to_combo[label] = (param, spec.kind)
                    self._send_probe(target, param, spec.render(domain))

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
    def _send_probe(target: str, param: str, probe_value: str) -> None:
        """GET ``target`` with ``param`` set to ``probe_value``, other params untouched."""
        parts = urlsplit(target)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
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
        param, kind = self._domain_to_combo.get(label, ("?", "ssrf"))
        meta = _VULN_META[kind]
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

        protocols_str = "/".join(protocols)
        description = meta["description"].format(protocols=protocols_str, param=param)

        return Finding(
            title=f"{meta['title_label']} confirmed via OOB callback: parameter '{param}'",
            severity=meta["severity"],
            confidence=confidence,
            url=self._target,
            parameter=param,
            payload=meta["payload_preview"].format(domain=f"{label}..."),
            evidence=f"{len(records)} interaction(s) ({protocols_str}) from {', '.join(remote_addrs)}",
            description=description,
            remediation=meta["remediation"],
            cvss_vector=meta["cvss_vector"],
            cvss_score=meta["cvss_score"],
            extra={
                "tool": self.name,
                "vuln_class": kind,
                "parameter": param,
                "domain_label": label,
                "protocols": protocols,
                "remote_addresses": remote_addrs,
                "interaction_count": len(records),
            },
        )
