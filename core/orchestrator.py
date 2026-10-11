"""
VortexDAST – core/orchestrator.py
────────────────────────────────────────────────────────────────────────────
Orchestration foundation: the :class:`ToolAdapter` contract and the plumbing
that lets VortexDAST *drive* external best-of-breed tools (nuclei, nmap, httpx,
sqlmap, …) and fold their output into the same :class:`~modules.base.Finding`
model the built-in scanner modules use.

Design mirrors ``modules/base.py``:

* :class:`ToolAdapter` is to external tools what ``BaseScannerModule`` is to
  built-in checks — a uniform ``run()`` interface the orchestrator can invoke
  without knowing a tool's internals.
* Adapters are **auto-discovered** from the ``adapters/`` package exactly as
  scanner modules are auto-discovered from ``modules/`` (see
  :func:`discover_adapters`), so adding a tool is zero-config: drop a file in
  ``adapters/``, subclass :class:`ToolAdapter`, set ``name`` + ``binary``.

Cross-cutting guarantees (see ``IMPROVEMENTS.md`` §2):

1. **Detection + fallback** — :meth:`ToolAdapter.is_available` gates every
   adapter via :func:`shutil.which`. An absent tool falls back to a built-in
   equivalent or logs a clean skip; a scan never *requires* an external tool.
2. **Command-injection safety** — commands are built as **argv lists** and run
   with ``shell=False`` through :func:`run_command`. A hostile target or
   parameter can never inject shell commands onto the operator's machine.
3. **Unified findings** — adapters emit the same :class:`Finding` objects, so
   reporting, SARIF, dedup and filtering work unchanged.
4. **Data passing** — a shared :class:`ScanContext` lets one tool's output feed
   the next (``nmap`` open ports → ``httpx`` live services → ``nuclei``).
5. **Timeouts + budgets** — every subprocess runs under a hard timeout.
"""

from __future__ import annotations

import abc
import importlib
import logging
import pkgutil
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Type

from modules.base import Finding, Severity

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Shared scan context (data passing between tools)
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class ScanContext:
    """
    Mutable state shared across an orchestrated run so one tool's output can
    feed the next (e.g. ``nmap`` discovers open ports → ``httpx`` probes them →
    ``nuclei`` templates the live HTTP services).

    Adapters read what they need and may append to the discovery collections.
    Fields are intentionally permissive: not every adapter populates every one.
    """

    target: str = ""
    """The primary scan target (URL or host) in scope."""

    scope_hosts: List[str] = field(default_factory=list)
    """Hosts/IPs authorised for this run. Adapters must stay within scope."""

    open_ports: Dict[str, List[int]] = field(default_factory=dict)
    """Discovered open TCP ports, keyed by host (populated by nmap/port_scan)."""

    http_services: List[str] = field(default_factory=list)
    """Live HTTP(S) base URLs discovered (populated by httpx)."""

    discovered_hosts: List[str] = field(default_factory=list)
    """Subdomains/hostnames discovered passively (populated by subfinder)."""

    #: Hard per-subprocess timeout, seconds. Individual adapters may lower this
    #: via their own ``default_timeout`` but must not exceed the run budget.
    tool_timeout: float = 600.0

    extra: Dict[str, Any] = field(default_factory=dict)
    """Free-form bag for adapter-specific hand-off data."""


# ─────────────────────────────────────────────────────────────────────────────
# Subprocess runner (argv-safe, timeout-bounded)
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class CommandResult:
    """Outcome of a :func:`run_command` invocation."""

    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    not_found: bool = False

    @property
    def ok(self) -> bool:
        """True when the process ran to completion without timing out."""
        return not self.timed_out and not self.not_found


def run_command(
    argv: List[str],
    *,
    timeout: float,
    input_text: Optional[str] = None,
) -> CommandResult:
    """
    Run ``argv`` as a child process with **no shell** and a hard timeout.

    This is the single choke-point through which every adapter shells out, so
    the command-injection guarantee is enforced in one place: callers pass a
    pre-split argv list (never an interpolated string), and ``shell=False`` is
    non-negotiable.

    Parameters
    ----------
    argv : list[str]
        The command and its arguments, already tokenised. Element ``0`` is the
        program; it is resolved against ``PATH`` by the OS.
    timeout : float
        Wall-clock seconds before the child is killed.
    input_text : str, optional
        Data to feed the child's stdin.

    Returns
    -------
    CommandResult
        Captured stdout/stderr plus ``timed_out`` / ``not_found`` flags. This
        function never raises for a missing binary or a timeout — it reports
        them on the result so adapters can fall back cleanly.
    """
    if not argv:
        raise ValueError("run_command requires a non-empty argv list")

    try:
        proc = subprocess.run(  # noqa: S603 — shell=False, argv list, trusted argv[0]
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            check=False,
        )
    except FileNotFoundError:
        logger.debug("Tool binary not found on PATH: %s", argv[0])
        return CommandResult(returncode=127, stdout="", stderr="", not_found=True)
    except subprocess.TimeoutExpired as exc:
        logger.warning("Tool %s timed out after %.0fs", argv[0], timeout)
        return CommandResult(
            returncode=-1,
            stdout=exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            stderr=exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
            timed_out=True,
        )

    return CommandResult(
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Parsing + finding-mapping helpers
# ─────────────────────────────────────────────────────────────────────────────


#: CSI escape sequences (colours, cursor/erase codes) emitted by some tools.
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def parse_jsonl(raw_output: str) -> Iterator[Dict[str, Any]]:
    """
    Yield one ``dict`` per non-blank line of JSONL (JSON-Lines) output.

    Tolerant by design: malformed lines are logged and skipped rather than
    aborting the whole parse, because a single bad record from an external
    tool must not sink an otherwise-good scan.

    Many ProjectDiscovery tools (nuclei ``-jsonl``, httpx ``-json``, subfinder)
    share this one-object-per-line convention, so adapters reuse this helper.

    Terminal control sequences are stripped first: some tools (e.g. ffuf
    ``-json``) prefix every record with an ANSI erase-line code (``ESC[2K``)
    even when stdout is not a TTY, which would otherwise make every line
    unparseable.
    """
    import json  # noqa: PLC0415 — local to keep the hot path lean

    for lineno, line in enumerate(raw_output.splitlines(), start=1):
        line = _ANSI_ESCAPE.sub("", line).strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except (ValueError, TypeError) as exc:
            logger.debug("Skipping malformed JSONL line %d: %s", lineno, exc)


#: External-tool severity label → VortexDAST :class:`Severity`. Covers the
#: common spellings emitted by nuclei/nmap/httpx (``info`` → informational,
#: ``unknown``/absent → informational).
_SEVERITY_ALIASES: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "unknown": Severity.INFORMATIONAL,
    "none": Severity.INFORMATIONAL,
}


def severity_from_label(label: Optional[str]) -> Severity:
    """Map an external tool's severity string to a :class:`Severity`."""
    if not label:
        return Severity.INFORMATIONAL
    return _SEVERITY_ALIASES.get(label.strip().lower(), Severity.INFORMATIONAL)


# ─────────────────────────────────────────────────────────────────────────────
# ToolAdapter contract
# ─────────────────────────────────────────────────────────────────────────────


class ToolAdapter(abc.ABC):
    """
    Abstract base for every external-tool integration.

    An adapter wraps one specialist binary: it knows how to detect it
    (:meth:`is_available`), how to build its argv (:meth:`build_command`), and
    how to translate its structured output into :class:`Finding` objects
    (:meth:`parse`). The concrete :meth:`run` ties these together with the
    detection/fallback and timeout guarantees so individual adapters stay small.

    Subclasses must set :attr:`name` and :attr:`binary` and implement
    :meth:`build_command` and :meth:`parse`. Everything else is provided.

    Example
    -------
    >>> class EchoAdapter(ToolAdapter):
    ...     name = "echo"
    ...     binary = "echo"
    ...     def build_command(self, target, ctx):
    ...         return [self.binary, target]
    ...     def parse(self, raw_output):
    ...         return []
    """

    #: Short machine-readable identifier used in CLI/reports (override).
    name: str = "base"

    #: Executable looked up on ``PATH`` via :func:`shutil.which` (override).
    binary: str = ""

    #: Human-readable description shown in ``--list-tools``.
    description: str = "Base tool adapter — not intended for direct use."

    #: Hard per-invocation timeout, seconds. May be overridden per adapter.
    default_timeout: float = 600.0

    # ── Detection ──────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """True when :attr:`binary` is resolvable on ``PATH``."""
        return bool(self.binary) and shutil.which(self.binary) is not None

    # ── Subclass responsibilities ────────────────────────────────────────────

    @abc.abstractmethod
    def build_command(self, target: str, ctx: ScanContext) -> List[str]:
        """
        Return the argv list to execute. Must be a tokenised list (never a
        shell string), configured so the tool emits machine-readable output
        (e.g. nuclei ``-jsonl``) on stdout.
        """

    @abc.abstractmethod
    def parse(self, raw_output: str) -> List[Finding]:
        """Translate the tool's captured stdout into :class:`Finding` objects."""

    # ── Fallback (optional override) ─────────────────────────────────────────

    def _fallback(self, target: str, ctx: ScanContext) -> List[Finding]:
        """
        Called when :meth:`is_available` is False. Default is a logged skip and
        no findings. Adapters with a built-in equivalent (e.g. nmap → the TCP
        ``port_scan`` module) override this to degrade gracefully.
        """
        logger.info(
            "Tool '%s' (binary %r) not installed — skipping.",
            self.name,
            self.binary,
        )
        return []

    # ── Orchestration entry point ────────────────────────────────────────────

    def run(self, target: str, ctx: ScanContext) -> List[Finding]:
        """
        Execute the adapter end-to-end: detect → run (or fall back) → parse.

        Honours the hard timeout (adapter's :attr:`default_timeout`, further
        capped by ``ctx.tool_timeout``) and never raises for a missing binary
        or a timeout — those degrade to the fallback / an empty result with a
        logged warning, so one flaky tool cannot abort the whole scan.
        """
        if not self.is_available():
            return self._fallback(target, ctx)

        timeout = min(self.default_timeout, ctx.tool_timeout)
        argv = self.build_command(target, ctx)
        logger.debug("Running %s: %s", self.name, " ".join(argv))

        result = run_command(argv, timeout=timeout)

        if result.not_found:
            # Raced with disappearance of the binary — fall back cleanly.
            return self._fallback(target, ctx)
        if result.timed_out:
            logger.warning("Adapter '%s' timed out; returning partial output.", self.name)
        elif result.returncode != 0:
            logger.warning(
                "Adapter '%s' exited %d: %s",
                self.name,
                result.returncode,
                result.stderr.strip()[:200],
            )

        try:
            return self.parse(result.stdout)
        except Exception as exc:  # pragma: no cover — defensive
            logger.error("Adapter '%s' failed to parse output: %s", self.name, exc)
            return []

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, binary={self.binary!r})"


# ─────────────────────────────────────────────────────────────────────────────
# Adapter auto-discovery + registry
# ─────────────────────────────────────────────────────────────────────────────


def discover_adapters() -> Dict[str, Type[ToolAdapter]]:
    """
    Auto-discover concrete :class:`ToolAdapter` subclasses in the ``adapters/``
    package, mirroring ``scanner._discover_modules``.

    Walks every submodule under ``adapters`` with :mod:`pkgutil`, imports each
    so its classes register in the subclass tree, then collects every concrete
    class declaring a non-empty, non-``"base"`` ``name``.

    Returns
    -------
    dict[str, type[ToolAdapter]]
        Mapping of ``adapter.name`` → adapter class.
    """
    try:
        import adapters as _adapters_pkg  # noqa: PLC0415 — deferred to avoid cycles
    except ImportError:
        logger.debug("No 'adapters' package found; adapter registry is empty.")
        return {}

    for _, modname, _ in pkgutil.walk_packages(
        path=_adapters_pkg.__path__,
        prefix=_adapters_pkg.__name__ + ".",
    ):
        try:
            importlib.import_module(modname)
        except Exception as exc:  # pragma: no cover
            logger.warning("Could not import adapter %s: %s", modname, exc)

    registry: Dict[str, Type[ToolAdapter]] = {}
    stack: List[Type[ToolAdapter]] = list(ToolAdapter.__subclasses__())
    while stack:
        cls = stack.pop()
        stack.extend(cls.__subclasses__())
        if cls.name and cls.name != "base":
            registry[cls.name] = cls

    return registry


#: Maps tool short-IDs → concrete adapter classes. Built lazily on first use.
ADAPTER_REGISTRY: Dict[str, Type[ToolAdapter]] = {}


def _registry() -> Dict[str, Type[ToolAdapter]]:
    """Return the adapter registry, building it on first access."""
    global ADAPTER_REGISTRY
    if not ADAPTER_REGISTRY:
        ADAPTER_REGISTRY = discover_adapters()
    return ADAPTER_REGISTRY


def available_tools() -> List[str]:
    """Sorted list of all known adapter names (installed or not)."""
    return sorted(_registry().keys())


def get_adapter(name: str) -> Optional[ToolAdapter]:
    """
    Instantiate the adapter registered under ``name``, or ``None`` if unknown.

    This is the orchestrator's public factory: the CLI resolves a ``--tools``
    selection to names, then asks for a live adapter instance per name without
    reaching into the registry internals.
    """
    cls = _registry().get(name)
    return cls() if cls is not None else None


def list_tools() -> List[Dict[str, Any]]:
    """
    Describe every known adapter for a ``--list-tools`` view: its name,
    wrapped binary, description, and whether that binary is installed.
    """
    rows: List[Dict[str, Any]] = []
    for name, cls in sorted(_registry().items()):
        inst = cls()
        rows.append(
            {
                "name": name,
                "binary": cls.binary,
                "description": cls.description,
                "installed": inst.is_available(),
            }
        )
    return rows
