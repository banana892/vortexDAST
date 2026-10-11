"""
VortexDAST – adapters/sqlmap_adapter.py
────────────────────────────────────────────────────────────────────────────
Adapter for **sqlmap** — confirms/exploits SQL-injection leads via sqlmap's
REST API server (``sqlmapapi.py``), per the IMPROVEMENTS.md Phase C design.

Unlike the subprocess+stdout adapters (nuclei, nmap, httpx, ffuf), sqlmap is
**stateful and long-running**, so it is driven over HTTP rather than a single
blocking subprocess call: start the API server, create a task, set options,
start the scan, poll for completion, collect the results, then tear down the
task and server. :meth:`SqlmapAdapter.run` overrides the base class's
subprocess-only ``run()`` for this reason, while :meth:`build_command` and
:meth:`parse` keep the same roles they have for every other adapter (argv to
launch the tool; translate its structured output into Findings) so sqlmap
still satisfies the one ``ToolAdapter`` interface.

Invocation
----------
``sqlmapapi -s --host 127.0.0.1 --port <ephemeral> --username <random>
--password <random>`` starts the REST API server, bound to localhost only,
behind a fresh random credential pair generated per run (never reused, never
exposed off-box). We then call, over HTTP with those credentials:

1. ``GET  /task/new``                 → ``taskid`` (also doubles as the
   server-ready check: retried until it answers or the budget elapses).
2. ``POST /option/<taskid>/set``      → ``{"url": target, "batch": true}``.
3. ``POST /scan/<taskid>/start``      → ``{}`` (options already set above).
4. ``GET  /scan/<taskid>/status``     → polled until no longer ``"running"``;
   if the adapter's own timeout elapses first, ``/scan/<taskid>/kill`` is
   called so no sqlmap engine process is left running after we move on.
5. ``GET  /scan/<taskid>/data``       → the JSON this adapter's :meth:`parse`
   consumes.
6. ``GET  /task/<taskid>/delete``     → always called (even on error) to free
   the task.

Only the ``TECHNIQUES`` content type (sqlmap's confirmed injection points) is
mapped into Findings. Enumeration content types (DBMS banner, current user,
dumped tables, …) are data sqlmap can be pushed to extract in a follow-up,
not a vulnerability in themselves.

Licence note
------------
sqlmap is GPL-licensed and invoked as a *separate program* over its REST API
(subprocess + HTTP, never imported), so no licence obligations flow into
VortexDAST — see IMPROVEMENTS.md §3.

Safety
------
The target reaches sqlmap only as an HTTP JSON value (never shell/argv), so
there is no command-injection surface here at all — stronger than the
argv-list guarantee the other adapters rely on. The API server binds to
``127.0.0.1`` only and never leaves random default credentials in place; the
server process is always terminated when :meth:`run` returns, success or not.
**Only scan targets you are authorised to test** — sqlmap can execute DBMS
commands with ``--risk``/``--level`` turned up (not done here: defaults are
used, matching the benign-by-default stance of the other adapters).
"""

from __future__ import annotations

import json
import logging
import secrets
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional

import requests

from core.cvss import build_vector, calculate as cvss_calc
from core.orchestrator import ScanContext, ToolAdapter
from modules.base import Confidence, Finding, Severity

logger = logging.getLogger(__name__)

# Confirmed SQLi via sqlmap is a direct observation, not a heuristic: same
# network-exploitable / full-impact profile modules/sqli_check.py uses for its
# own confirmed (error-based) case.
_CVSS_VECTOR_CONFIRMED_SQLI = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"
)
_CVSS_SCORE_CONFIRMED_SQLI: float = cvss_calc(_CVSS_VECTOR_CONFIRMED_SQLI)  # 9.8

#: How often to poll /scan/<id>/status while a scan is running.
_POLL_INTERVAL = 1.0
#: Per-HTTP-call timeout (server is localhost; a hang means something's wrong).
_HTTP_TIMEOUT = 5.0


class SqlmapAdapter(ToolAdapter):
    """Drive sqlmap's REST API server and map confirmed injections into Findings."""

    name: str = "sqlmap"
    #: The literal executable this adapter spawns (see module docstring);
    #: the ``sqlmap`` wrapper most installs provide does not expose ``-s``.
    binary: str = "sqlmapapi"
    description: str = (
        "SQL-injection confirmation/exploitation via sqlmap's REST API server. "
        "Turns a 'possible SQLi' lead into a confirmed finding with technique, "
        "DBMS and payload detail. Optional external tool; requires 'sqlmapapi' "
        "on PATH (bundled with sqlmap)."
    )
    #: sqlmap's own detection phase can take a couple of minutes per target.
    default_timeout: float = 300.0

    def __init__(self) -> None:
        self.host: str = "127.0.0.1"
        self.port: int = self._free_port()
        self.username: str = secrets.token_hex(8)
        self.password: str = secrets.token_hex(8)
        #: Stashed by run() so parse() can attach the scanned URL to each
        #: Finding — sqlmap's /scan/<id>/data response never echoes it back.
        self._target: str = ""

    @staticmethod
    def _free_port() -> int:
        """Ask the OS for an unused localhost TCP port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    # ── ToolAdapter contract ──────────────────────────────────────────────

    def build_command(self, target: str, ctx: ScanContext) -> List[str]:
        """Argv to launch sqlmap's REST API server, bound to localhost."""
        return [
            self.binary,
            "-s",
            "--host",
            self.host,
            "--port",
            str(self.port),
            "--username",
            self.username,
            "--password",
            self.password,
        ]

    def parse(self, raw_output: str) -> List[Finding]:
        """Translate a ``/scan/<id>/data`` JSON response into Findings."""
        if not raw_output:
            return []
        try:
            payload = json.loads(raw_output)
        except (ValueError, TypeError) as exc:
            logger.debug("sqlmap adapter: could not parse scan data: %s", exc)
            return []

        findings: List[Finding] = []
        for entry in payload.get("data") or []:
            if not isinstance(entry, dict) or entry.get("type_name") != "TECHNIQUES":
                continue
            for injection in entry.get("value") or []:
                finding = self._map_injection(injection)
                if finding is not None:
                    findings.append(finding)
        return findings

    # ── Orchestration entry point (overrides the subprocess-only default) ──

    def run(self, target: str, ctx: ScanContext) -> List[Finding]:
        if not self.is_available():
            return self._fallback(target, ctx)

        self._target = target
        deadline = time.monotonic() + min(self.default_timeout, ctx.tool_timeout)
        base = f"http://{self.host}:{self.port}"
        auth = (self.username, self.password)

        try:
            proc = subprocess.Popen(
                self.build_command(target, ctx),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return self._fallback(target, ctx)

        try:
            taskid = self._wait_for_task(base, auth, deadline)
            if taskid is None:
                logger.warning("sqlmap API server did not become ready in time.")
                return []
            try:
                return self._run_task(base, auth, taskid, target, deadline)
            finally:
                self._call(requests.get, f"{base}/task/{taskid}/delete", auth)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _run_task(
        self,
        base: str,
        auth: tuple[str, str],
        taskid: str,
        target: str,
        deadline: float,
    ) -> List[Finding]:
        set_resp = self._call(
            requests.post,
            f"{base}/option/{taskid}/set",
            auth,
            json={"url": target, "batch": True},
        )
        if not set_resp or not set_resp.get("success"):
            logger.warning("sqlmap: failed to set scan options: %s", set_resp)
            return []

        start_resp = self._call(requests.post, f"{base}/scan/{taskid}/start", auth, json={})
        if not start_resp or not start_resp.get("success"):
            logger.warning("sqlmap: failed to start scan: %s", start_resp)
            return []

        self._poll_until_done(base, auth, taskid, deadline)

        data_resp = self._call(requests.get, f"{base}/scan/{taskid}/data", auth)
        if data_resp is None:
            return []
        return self.parse(json.dumps(data_resp))

    # ── HTTP helpers ─────────────────────────────────────────────────────

    def _wait_for_task(
        self, base: str, auth: tuple[str, str], deadline: float
    ) -> Optional[str]:
        """Poll ``/task/new`` until the server answers or the budget elapses."""
        while time.monotonic() < deadline:
            resp = self._call(requests.get, f"{base}/task/new", auth, timeout=1.0)
            if resp and resp.get("success"):
                return resp.get("taskid")
            time.sleep(0.2)
        return None

    def _poll_until_done(
        self, base: str, auth: tuple[str, str], taskid: str, deadline: float
    ) -> None:
        while time.monotonic() < deadline:
            status = self._call(requests.get, f"{base}/scan/{taskid}/status", auth)
            if status and status.get("status") != "running":
                return
            time.sleep(_POLL_INTERVAL)
        logger.warning("sqlmap scan exceeded its time budget; killing it.")
        self._call(requests.get, f"{base}/scan/{taskid}/kill", auth)

    @staticmethod
    def _call(
        method: Any,
        url: str,
        auth: tuple[str, str],
        timeout: float = _HTTP_TIMEOUT,
        **kwargs: Any,
    ) -> Optional[Dict[str, Any]]:
        """POST/GET the sqlmap API, tolerating a not-yet-ready or flaky server."""
        try:
            resp = method(url, auth=auth, timeout=timeout, **kwargs)
        except requests.exceptions.RequestException as exc:
            logger.debug("sqlmap API call to %s failed: %s", url, exc)
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    # ── Internal mapping ─────────────────────────────────────────────────

    def _map_injection(self, injection: Any) -> Optional[Finding]:
        if not isinstance(injection, dict):
            return None

        place = injection.get("place") or "?"
        parameter = injection.get("parameter") or "?"
        dbms = injection.get("dbms")
        techniques = [t for t in (injection.get("data") or []) if isinstance(t, dict)]
        technique_names = [t["technique"] for t in techniques if t.get("technique")]

        evidence = "; ".join(
            " | ".join(
                part
                for part in (
                    t.get("technique"),
                    f"payload={t['payload']}" if t.get("payload") else None,
                )
                if part
            )
            for t in techniques
        )

        description = f"sqlmap confirmed SQL injection via the {place} parameter '{parameter}'"
        if dbms:
            description += f" (DBMS: {dbms})"

        return Finding(
            title=f"Confirmed SQL Injection: {place} parameter '{parameter}'",
            severity=Severity.CRITICAL,
            confidence=Confidence.CERTAIN,
            url=self._target,
            parameter=parameter,
            payload=techniques[0].get("payload") if techniques else None,
            evidence=evidence,
            description=description,
            remediation=(
                "Use parameterised queries / prepared statements for all "
                "database access; never interpolate user input into SQL."
            ),
            cvss_vector=_CVSS_VECTOR_CONFIRMED_SQLI,
            cvss_score=_CVSS_SCORE_CONFIRMED_SQLI,
            extra={
                "tool": self.name,
                "place": place,
                "parameter": parameter,
                "dbms": dbms,
                "dbms_version": injection.get("dbms_version"),
                "os": injection.get("os"),
                "techniques": technique_names,
            },
        )
