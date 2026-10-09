"""
VortexDAST – adapters/ffuf_adapter.py
────────────────────────────────────────────────────────────────────────────
Adapter for **ffuf** ("Fuzz Faster U Fool") — a fast web content-discovery
fuzzer.

ffuf is the high-throughput counterpart of the built-in ``dir_fuzzer`` module:
it brute-forces paths under the target origin and reports which ones respond.
By default it runs VortexDAST's own curated sensitive-path catalogue
(``payloads/common_paths.json`` — ``.env``, ``.git/``, backups, admin panels,
API docs, …) so each hit keeps the catalogue's severity and description. An
operator can point it at any larger wordlist with ``--ffuf-wordlist``.

Invocation
----------
``ffuf -u <origin>/FUZZ -w <wordlist> -json -s -noninteractive -ac`` prints one
JSON record per hit on stdout. ``-ac`` (auto-calibration) filters soft-404 /
catch-all responses, the main source of false positives in path brute-forcing.
``-maxtime`` makes ffuf stop itself just inside the orchestrator's hard
timeout, so a long run still flushes the hits it found instead of being killed
with nothing to show.

Real-output quirks handled
--------------------------
* Every ``-json`` record is prefixed with an ANSI erase-line code (``ESC[2K``)
  even when stdout is a pipe — stripped by :func:`core.orchestrator.parse_jsonl`.
* The ``input.FUZZ`` value is base64-encoded and, with ``-ac``, can belong to a
  calibration request rather than the hit, so the record's ``url`` is treated as
  the source of truth for which path was found.

Licence note
------------
ffuf is MIT-licensed and invoked as a *separate program* (subprocess).

Safety
------
The URL, wordlist path, headers and cookie are each passed as single argv
elements through :func:`core.orchestrator.run_command` (``shell=False``).
ffuf honours the scan's ``--rate-limit`` and thread count. It sends many
requests — **only fuzz targets you are authorised to test.**
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from core.orchestrator import ScanContext, ToolAdapter, parse_jsonl
from modules.base import Confidence, Finding, Severity

logger = logging.getLogger(__name__)

_CATALOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "payloads",
    "common_paths.json",
)

_SEVERITY: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
}

#: One step down, used for 401/403 hits (exists, but access is restricted) —
#: the same downgrade the built-in ``dir_fuzzer`` applies.
_DOWNGRADE: Dict[Severity, Severity] = {
    Severity.CRITICAL: Severity.MEDIUM,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFORMATIONAL,
    Severity.INFORMATIONAL: Severity.INFORMATIONAL,
}

#: Seconds of headroom between ffuf's own ``-maxtime`` and the hard kill.
_MAXTIME_MARGIN = 5


def _load_catalog() -> Dict[str, Dict[str, str]]:
    """Load ``common_paths.json`` keyed by normalised path (no leading ``/``)."""
    try:
        with open(_CATALOG_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        logger.warning("ffuf: could not load %s: %s", _CATALOG_PATH, exc)
        return {}
    catalog: Dict[str, Dict[str, str]] = {}
    for entry in data.get("paths", []):
        path = str(entry.get("path", "")).strip().lstrip("/")
        if path:
            catalog[path.rstrip("/")] = {
                "path": "/" + path,
                "category": str(entry.get("category", "")),
                "severity": str(entry.get("severity", "informational")).lower(),
                "description": str(entry.get("description", "")),
            }
    return catalog


class FfufAdapter(ToolAdapter):
    """Drive ``ffuf`` for content discovery and map its hits into Findings."""

    name: str = "ffuf"
    binary: str = "ffuf"
    description: str = (
        "Fast web content-discovery fuzzer (ffuf). Brute-forces paths under the "
        "target origin — by default VortexDAST's curated sensitive-path list "
        "(.env, .git, backups, admin panels), or any list via --ffuf-wordlist. "
        "Auto-calibrates away soft-404s. Optional external tool; sends many "
        "requests — authorised targets only."
    )
    default_timeout: float = 900.0

    def __init__(self) -> None:
        self._catalog = _load_catalog()
        self._temp_wordlist: Optional[str] = None

    # ── Wordlist ───────────────────────────────────────────────────────────

    def _wordlist(self, ctx: ScanContext) -> str:
        """Operator wordlist if given, else a temp file built from the catalogue."""
        custom = ctx.extra.get("ffuf_wordlist")
        if custom:
            return str(custom)
        fd, path = tempfile.mkstemp(prefix="vortex-ffuf-", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for key in self._catalog:
                fh.write(key + "\n")
        self._temp_wordlist = path
        return path

    # ── Command building ─────────────────────────────────────────────────────

    @staticmethod
    def _origin(target: str) -> str:
        parts = urlsplit(target)
        if parts.scheme and parts.netloc:
            return f"{parts.scheme}://{parts.netloc}"
        return "http://" + target.strip().strip("/")

    def build_command(self, target: str, ctx: ScanContext) -> List[str]:
        """
        Build the ffuf argv: fuzz ``<origin>/FUZZ`` with JSON-Lines output,
        auto-calibration, and the scan's own rate limit / concurrency / auth.
        """
        budget = min(self.default_timeout, ctx.tool_timeout)
        maxtime = max(1, int(budget) - _MAXTIME_MARGIN)

        argv = [
            self.binary,
            "-u", self._origin(target) + "/FUZZ",
            "-w", self._wordlist(ctx),
            "-json", "-s", "-noninteractive",
            "-ac",
            "-maxtime", str(maxtime),
        ]

        threads = ctx.extra.get("threads")
        if isinstance(threads, int) and threads > 0:
            argv += ["-t", str(threads)]
        rate = ctx.extra.get("rate_limit_rps")
        if isinstance(rate, (int, float)) and rate > 0:
            # ffuf's -rate is an integer req/s; never round a limit up to 0.
            argv += ["-rate", str(max(1, int(rate)))]
        timeout = ctx.extra.get("request_timeout")
        if isinstance(timeout, (int, float)) and timeout > 0:
            argv += ["-timeout", str(int(timeout))]

        headers = ctx.extra.get("headers") or {}
        for key, value in headers.items():
            argv += ["-H", f"{key}: {value}"]
        cookie = ctx.extra.get("cookie")
        if cookie:
            argv += ["-b", str(cookie)]
        return argv

    def run(self, target: str, ctx: ScanContext) -> List[Finding]:
        """Run via the base contract, always removing the temp wordlist."""
        try:
            return super().run(target, ctx)
        finally:
            if self._temp_wordlist:
                try:
                    os.unlink(self._temp_wordlist)
                except OSError:
                    pass
                self._temp_wordlist = None

    # ── Parsing ──────────────────────────────────────────────────────────────

    def parse(self, raw_output: str) -> List[Finding]:
        """Translate ffuf JSONL hits into :class:`Finding` objects."""
        findings: List[Finding] = []
        seen: set = set()
        for record in parse_jsonl(raw_output):
            finding = self._map_record(record)
            if finding is not None and finding.url not in seen:
                seen.add(finding.url)
                findings.append(finding)
        return findings

    def _catalog_entry(self, url: str) -> Tuple[str, Optional[Dict[str, str]]]:
        """Return the hit's path and its catalogue entry (if it is one)."""
        path = urlsplit(url).path or "/"
        return path, self._catalog.get(path.strip("/"))

    def _map_record(self, record: Dict[str, Any]) -> Optional[Finding]:
        if not isinstance(record, dict):
            return None
        url = record.get("url") or ""
        status = record.get("status")
        if not url or not isinstance(status, int):
            return None

        path, entry = self._catalog_entry(str(url))
        redirect = record.get("redirectlocation") or ""
        length = record.get("length")

        if entry is not None:
            severity = _SEVERITY.get(entry["severity"], Severity.INFORMATIONAL)
            category = entry["category"]
            what = entry["description"]
        else:
            # Custom-wordlist hit: no catalogue context, so stay conservative.
            severity = Severity.LOW if status == 200 else Severity.INFORMATIONAL
            category = ""
            what = "Path discovered by content brute-forcing."

        if status in (401, 403):
            severity = _DOWNGRADE[severity]
        elif 300 <= status < 400:
            # A redirect proves little (often a trailing-slash bounce).
            severity = Severity.INFORMATIONAL

        confidence = Confidence.FIRM if status == 200 else Confidence.TENTATIVE

        title = {
            "admin": "Discovered Administrative Portal",
            "api": "Discovered API Schema / Documentation",
            "backup": "Discovered Backup / Archive File",
            "vcs": "Exposed Version Control Artifact",
            "config": "Exposed Configuration File",
        }.get(category, "Discovered Path")

        evidence = f"HTTP {status}"
        if length is not None:
            evidence += f", {length} bytes"
        if redirect:
            evidence += f", redirects to {redirect}"

        return Finding(
            title=f"{title}: {path}",
            severity=severity,
            confidence=confidence,
            url=str(url),
            parameter=None,
            payload=path,
            evidence=evidence,
            description=f"ffuf found '{path}' on the server ({what}). Status: HTTP {status}.",
            remediation=(
                "Remove files that should not be deployed (configs, backups, VCS "
                "metadata) and restrict administrative or internal endpoints with "
                "access rules, IP allowlisting, or strong authentication."
            ),
            extra={
                "tool": self.name,
                "status": status,
                "length": length,
                "words": record.get("words"),
                "lines": record.get("lines"),
                "content_type": record.get("content-type") or None,
                "redirect": redirect or None,
                "category": category or None,
            },
        )
