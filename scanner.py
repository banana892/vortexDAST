#!/usr/bin/env python3
"""
VortexDAST – scanner.py
────────────────────────────────────────────────────────────────────────────
Main CLI entrypoint and scan orchestrator.

Workflow
--------
1.  Parse CLI arguments.
2.  Load ``config.yaml`` (falls back to built-in defaults if not found).
3.  Apply CLI overrides on top of config values.
4.  Initialise a shared :class:`~core.requester.Requester` session.
5.  Run the :class:`~core.crawler.Crawler` to build the attack surface
    (displayed with a live Rich progress spinner).
6.  Sequentially execute each selected scanner module against every endpoint
    (displayed with a live Rich progress bar with ETA).
7.  Aggregate all :class:`~modules.base.Finding` objects.
8.  Render a Rich terminal dashboard via :class:`~core.reporter.Reporter`.
9.  Save JSON and/or Markdown report files if ``--output`` is specified.

CLI Usage
---------
::

    vortex -u https://target.example.com
    vortex -u http://testphp.vulnweb.com -m xss_check,sqli_check --max-depth 2
    vortex -u https://app.local -k -o reports/result.json
    vortex -u http://target.com --rate-limit 2 --modules all -o scan.md
    vortex --list-modules

    # or equivalently:
    vortexdast -u https://target.example.com

Module names
------------
Discovered dynamically from the ``modules/`` package. Use ``--list-modules``
to print all registered modules with their short IDs and descriptions.
"""

from __future__ import annotations

import argparse
import importlib
import logging
import os
import pkgutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple, Type
from urllib.parse import urlsplit

import yaml
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

try:  # Installed distribution metadata is the source of truth for the version.
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("vortexdast")
except Exception:  # pragma: no cover — running from a source checkout
    __version__ = "1.0.0"

# Project-root path manipulation so the script runs from the repo root.
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core import crawl_cache
from core.crawler import CrawlResult, CrawledEndpoint, Crawler
from core.endpoint_group import group_endpoints
from core.profiles import (
    PROFILE_NAMES,
    ConfigError,
    apply_env_overrides,
    apply_profile,
    validate_config,
)
from core.engine import _anomaly_findings, _collect_response_features
from core.notify import WEBHOOK_FORMATS, build_payload, send_webhook
from core.filters import SEVERITY_ORDER, FilterConfigError, FindingFilter, load_suppression_rules
from core.reporter import Reporter
from core.requester import Requester
from core.theme import (
    DEFAULT_THEME_NAME,
    THEME_NAMES,
    ThemeError,
    VortexTheme,
    build_console,
    get_theme,
)
from core import ui
from modules.base import CONFIDENCE_ORDER, BaseScannerModule, Finding

# ─────────────────────────────────────────────────────────────────────────────
# Module registry – dynamic discovery
# ─────────────────────────────────────────────────────────────────────────────


def _discover_modules() -> Dict[str, Type[BaseScannerModule]]:
    """
    Auto-discover and map all concrete :class:`~modules.base.BaseScannerModule`
    subclasses found in the ``modules/`` package.

    The function walks every submodule under the ``modules`` package using
    :mod:`pkgutil`, imports each one, then introspects the subclass tree of
    :class:`BaseScannerModule` to collect all concrete (non-abstract) classes
    that declare a non-empty, non-``"base"`` ``name`` attribute.

    Returns
    -------
    dict[str, type[BaseScannerModule]]
        Mapping of ``module.name`` → module class, ready to use as
        ``MODULE_REGISTRY``.

    Notes
    -----
    Adding a new scanner module is now zero-config: drop a file in
    ``modules/``, subclass ``BaseScannerModule``, set ``name`` and
    ``description``, and it will be auto-registered on the next run.
    """
    import modules as _modules_pkg  # noqa: PLC0415 – deferred to avoid circular imports

    # Walk and import every submodule so their classes are registered in the
    # subclass tree before we introspect it.
    for _, modname, _ in pkgutil.walk_packages(
        path=_modules_pkg.__path__,
        prefix=_modules_pkg.__name__ + ".",
    ):
        try:
            importlib.import_module(modname)
        except Exception as exc:  # pragma: no cover
            logging.getLogger("vortexdast").warning(
                "Could not import module %s: %s", modname, exc
            )

    registry: Dict[str, Type[BaseScannerModule]] = {}
    stack: List[Type[BaseScannerModule]] = list(BaseScannerModule.__subclasses__())

    while stack:
        cls = stack.pop()
        stack.extend(cls.__subclasses__())
        # Skip abstract bases and the placeholder base entry.
        if cls.name and cls.name != "base":
            registry[cls.name] = cls

    return registry


#: Maps CLI module short-IDs → concrete module classes.
#: Built once at import-time via dynamic subclass introspection.
MODULE_REGISTRY: Dict[str, Type[BaseScannerModule]] = _discover_modules()

#: Modules that are registered and runnable, but excluded from "--modules all".
#: They perform activity distinct enough (e.g. raw network port scanning) that
#: the operator must opt in explicitly.
_OPT_IN_MODULES: frozenset = frozenset({"port_scan"})

_DEFAULT_CONFIG_PATH = os.path.join(_ROOT, "config.yaml")

# ─────────────────────────────────────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────────────────────────────────────


def _configure_logging(verbose: bool, console: Optional[Console] = None) -> None:
    """
    Configure structured logging with RichHandler for prettier output.

    Passing the themed console makes log records share the scan's palette, so
    style tokens such as ``[vortex.accent]`` resolve inside log messages.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=console,
                rich_tracebacks=True,
                markup=True,
                show_path=False,
                show_time=verbose,
                omit_repeated_times=False,
            )
        ],
        force=True,
    )
    # Keep a default run readable: each phase prints its own status line, so
    # the per-request chatter from the core.* loggers is held back to
    # --verbose. Warnings and errors always come through.
    logging.getLogger("core").setLevel(logging.DEBUG if verbose else logging.WARNING)


logger = logging.getLogger("vortexdast")


# ─────────────────────────────────────────────────────────────────────────────
# Configuration loader
# ─────────────────────────────────────────────────────────────────────────────


def _load_config(path: str) -> Dict[str, Any]:
    """
    Load ``config.yaml`` from ``path``.

    Falls back to a safe built-in default dict if the file is missing so the
    scanner can run without a config file.

    Parameters
    ----------
    path : str
        Path to the YAML configuration file.

    Returns
    -------
    dict
        Parsed configuration dictionary.
    """
    _DEFAULTS: Dict[str, Any] = {
        "crawler":   {"max_depth": 3, "dynamic_crawl": False},
        "requester": {
            "timeout": 10,
            "user_agent": "VortexDAST/1.0",
            "rate_limit_rps": 5,
            "verify_ssl": True,
            "max_retries": 3,
            "proxy": None,
        },
        "scope": {
            "allowed_domains": [],
            "allowed_paths": [],
            "excluded_paths": ["/logout", "/signout", "/delete"],
            "excluded_extensions": [
                ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
                ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
            ],
        },
        "output": {"report_dir": "./reports", "formats": ["json"], "verbose": False},
    }

    if not os.path.isfile(path):
        logger.warning("config.yaml not found at %s — using built-in defaults.", path)
        return _DEFAULTS

    try:
        with open(path, "r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        # Deep-merge: loaded values override defaults.
        for section, values in loaded.items():
            if isinstance(values, dict) and section in _DEFAULTS:
                _DEFAULTS[section].update(values)
            else:
                _DEFAULTS[section] = values
        return _DEFAULTS
    except yaml.YAMLError as exc:
        logger.error("Failed to parse config.yaml: %s — using defaults.", exc)
        return _DEFAULTS


# ─────────────────────────────────────────────────────────────────────────────
# Rich helpers
# ─────────────────────────────────────────────────────────────────────────────


def _print_module_table(
    console: Optional[Console] = None,
    theme: Optional[VortexTheme] = None,
) -> None:
    """
    Pretty-print all registered scanner modules as a themed Rich table.

    Columns: **ID** (the ``--modules`` name), **Class** (Python class name)
    and **Description**.

    Parameters
    ----------
    console : rich.console.Console | None
        Rich console to render into. A themed console is created when omitted.
    theme : core.theme.VortexTheme | None
        Palette to render with. Defaults to the built-in default theme.
    """
    th = theme or get_theme()
    con = console or build_console(th)

    table = Table(
        title=Text(
            f"VortexDAST {th.glyphs.dash} Registered Scanner Modules",
            style=th.style("vortex.title"),
        ),
        title_justify="left",
        show_header=True,
        box=th.table_box,
        header_style=th.style("vortex.header"),
        border_style=th.style("vortex.border"),
        # Descriptions fold over several lines, so separate the rows.
        show_lines=True,
        padding=(0, 1),
    )
    table.add_column("ID", no_wrap=True, min_width=16, style=th.style("vortex.module"))
    table.add_column("Class", no_wrap=True, min_width=22, style=th.style("vortex.muted"))
    table.add_column("Description", overflow="fold")

    for mod_id, cls in sorted(MODULE_REGISTRY.items()):
        table.add_row(mod_id, cls.__name__, cls.description)

    con.print()
    con.print(table)

    footer = Text("  ")
    footer.append(str(len(MODULE_REGISTRY)), style=th.style("vortex.value"))
    footer.append(" module(s) registered. Select with ", style=th.style("vortex.muted"))
    footer.append("-m MODULE_ID", style=th.style("vortex.accent"))
    footer.append(" or ", style=th.style("vortex.muted"))
    footer.append("--modules all", style=th.style("vortex.accent"))
    footer.append(".", style=th.style("vortex.muted"))
    con.print(footer)
    con.print()


def _resolve_theme(
    args: argparse.Namespace,
    config: Optional[Dict[str, Any]] = None,
) -> Tuple[VortexTheme, bool]:
    """
    Pick the active theme, honouring the project's usual precedence:

        --theme flag  >  VORTEX_THEME env  >  config.yaml ui.theme  >  default

    ``VORTEX_THEME`` reaches us through ``config["ui"]["theme"]`` because
    :func:`~core.profiles.apply_env_overrides` has already layered it on.

    Returns
    -------
    tuple[VortexTheme, bool]
        The resolved theme and whether colour should be suppressed entirely.

    Raises
    ------
    core.theme.ThemeError
        If an unknown theme name was requested.
    """
    ui_cfg = (config or {}).get("ui", {}) or {}
    # Before config.yaml is loaded (``--list-themes``, bootstrap logging) the
    # env var has not been layered in yet, so read it directly.
    env_theme = os.environ.get("VORTEX_THEME") if config is None else None
    env_no_color = os.environ.get("VORTEX_NO_COLOR") if config is None else None

    name = getattr(args, "theme", None) or env_theme or ui_cfg.get("theme") or DEFAULT_THEME_NAME
    no_color = bool(
        getattr(args, "no_color", False)
        or (env_no_color or "").strip().lower() in ("1", "true", "yes", "on")
        or ui_cfg.get("no_color", False)
    )
    return get_theme(name), no_color


def _make_fuzz_progress(console: Console, theme: Optional[VortexTheme] = None) -> Progress:
    """
    Build a :class:`rich.progress.Progress` instance configured for the fuzz phase.

    Columns: spinner | description text | bar | X/Y | ETA. The spinner and bar
    colours come from ``theme``.

    Parameters
    ----------
    console : Console
        The shared Rich console to render into.
    theme : core.theme.VortexTheme | None
        Palette for the spinner and bar. Defaults to the default theme.

    Returns
    -------
    rich.progress.Progress
        Ready-to-use progress context (not yet started).
    """
    th = theme or get_theme()
    return Progress(
        SpinnerColumn(spinner_name=th.spinner, style=th.style("vortex.accent")),
        TextColumn("{task.description}", justify="left"),
        BarColumn(
            bar_width=32,
            style=th.style("vortex.border"),
            complete_style=th.style("vortex.accent"),
            finished_style=th.style("vortex.success"),
        ),
        TaskProgressColumn(),
        TextColumn("[vortex.muted]ETA[/vortex.muted]"),
        TimeRemainingColumn(),
        console=console,
        transient=False,
        expand=False,
    )


# ─────────────────────────────────────────────────────────────────────────────
# CLI argument parser
# ─────────────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    """Construct and return the argparse argument parser."""
    parser = argparse.ArgumentParser(
        prog="vortexdast",
        description=(
            "VortexDAST — Lightweight Dynamic Application Security Testing Framework.\n"
            "Crawls a target web application and runs configurable vulnerability modules."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  vortex --list-modules\n"
            "  vortex -u http://testphp.vulnweb.com\n"
            "  vortex -u https://app.local -k -m xss_check,sqli_check\n"
            "  vortex -u http://target.com --max-depth 2 -o results.json\n"
            "  vortex -u http://target.com --modules all --rate-limit 20 --concurrency 20\n"
            "  vortex -u http://target.com --max-endpoints 10 --timeout 5 --rate-limit 10\n"
            "  vortexdast -u http://target.com --dynamic --verbose\n"
            "  vortex --list-themes\n"
            "  vortex -u http://target.com --theme neon\n"
            "  vortex -u http://target.com --theme mono --no-color -o scan.json\n"
        ),
    )

    # ── Discovery ─────────────────────────────────────────────────────────────
    parser.add_argument(
        "--list-modules",
        action="store_true",
        default=False,
        help=(
            "Print a Rich table of all registered scanner modules with their "
            "IDs and descriptions, then exit with code 0."
        ),
    )

    parser.add_argument(
        "--list-themes",
        action="store_true",
        default=False,
        help=(
            "Print all available colour themes with a live palette preview, "
            "then exit with code 0."
        ),
    )

    # ── Appearance ───────────────────────────────────────────────────────────
    parser.add_argument(
        "--theme",
        choices=THEME_NAMES,
        default=None,
        metavar="NAME",
        help=(
            "Terminal colour theme: " + ", ".join(THEME_NAMES) + ". "
            f"Default: {DEFAULT_THEME_NAME} (near-monochrome). "
            "Run --list-themes to preview them. Also settable via config.yaml "
            "ui.theme or the VORTEX_THEME env var."
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help=(
            "Strip all colour from terminal output while keeping the layout. "
            "Applies on top of --theme; useful for logs and dumb terminals."
        ),
    )

    # ── Required ─────────────────────────────────────────────────────────────
    parser.add_argument(
        "--target", "-u",
        required=False,   # Not required when --list-modules is used.
        default=None,
        metavar="URL",
        help="Target base URL to scan (required unless --list-modules). Example: https://target.example.com",
    )

    # ── Scan configuration ────────────────────────────────────────────────────
    parser.add_argument(
        "--max-depth",
        type=int,
        default=None,
        metavar="N",
        help="Crawler BFS recursion depth (default: value from config.yaml, usually 3).",
    )
    parser.add_argument(
        "--modules", "-m",
        default="all",
        metavar="MODULES",
        help=(
            'Comma-separated list of modules to run, or "all". '
            f"Run --list-modules to see all available IDs. "
            "Default: all"
        ),
    )
    parser.add_argument(
        "--recon-only",
        action="store_true",
        default=False,
        help=(
            "Run only reconnaissance modules (tech_detect, dir_fuzzer, param_fuzzer). "
            "Overrides --modules."
        ),
    )
    parser.add_argument(
        "--port-scan",
        action="store_true",
        default=False,
        help=(
            "Enable the host-scoped TCP connect port scan (opt-in; excluded from "
            "--modules all). Scans only the target host — no CIDR/subnet expansion."
        ),
    )
    parser.add_argument(
        "--ports",
        default=None,
        metavar="LIST",
        help=(
            "Comma-separated ports and ranges to scan, e.g. '22,80,8000-8100'. "
            "Implies --port-scan. Default: curated common-ports list."
        ),
    )
    parser.add_argument(
        "--port-scan-timeout",
        type=float,
        default=1.5,
        metavar="SECS",
        help="Per-port TCP connect timeout for --port-scan (default: 1.5).",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=None,
        metavar="RPS",
        help=(
            "Override requests-per-second rate limit (0 = disabled). "
            "Default from config.yaml (usually 5). "
            "Safe to raise to 20.0 for authorised remote targets."
        ),
    )
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Number of concurrent worker threads used by scanner modules. "
            "Higher values reduce wall-clock time for probe-heavy modules (XSS, SQLi, SSRF). "
            "Default: 10 (or the --profile / config value). Recommended range: 5–20. "
            "See also: --concurrency (alias that takes precedence)."
        ),
    )
    parser.add_argument(
        "--profile",
        choices=PROFILE_NAMES,
        default=None,
        help=(
            "Pre-built settings bundle: 'aggressive' (fast, noisy), 'balanced' "
            "(default-like), or 'quiet' (slow, gentle). Explicit flags and "
            "VORTEX_* env vars still override it."
        ),
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Number of concurrent worker threads (alias for --threads; "
            "takes precedence when both are specified). "
            "Recommended range: 5–20."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        metavar="SECS",
        help=(
            "Per-request HTTP timeout in seconds. "
            "Overrides the value in config.yaml (usually 10 s). "
            "Useful for slow targets (raise to 30) or CI speed (lower to 5)."
        ),
    )
    parser.add_argument(
        "--max-endpoints",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Cap the number of crawled endpoints passed to scanner modules. "
            "Useful for quick reconnaissance scans (e.g. --max-endpoints 10). "
            "Default: unlimited."
        ),
    )
    parser.add_argument(
        "--insecure", "-k",
        action="store_true",
        default=False,
        help="Disable SSL certificate verification (for self-signed certs in local labs).",
    )
    parser.add_argument(
        "--dynamic",
        action="store_true",
        default=False,
        help=(
            "Enable Playwright headless browser crawling for JS-rendered SPAs. "
            "Requires: playwright install chromium"
        ),
    )
    parser.add_argument(
        "--config",
        default=_DEFAULT_CONFIG_PATH,
        metavar="PATH",
        help=f"Path to config.yaml (default: {_DEFAULT_CONFIG_PATH}).",
    )
    parser.add_argument(
        "--proxy",
        default=None,
        metavar="URL",
        help="HTTP proxy URL (e.g. http://127.0.0.1:8080).",
    )

    # ── Authentication & session ────────────────────────────────────────────
    parser.add_argument(
        "--cookie", "-C",
        default=None,
        metavar="STRING",
        help=(
            'Inject session cookies into every request. '
            'Format: "NAME=VALUE; NAME2=VALUE2" (same as a browser Cookie header). '
            'Example: --cookie "JSESSIONID=abc123; auth=true"'
        ),
    )
    parser.add_argument(
        "--header", "-H",
        action="append",
        default=None,
        metavar="HEADER",
        help=(
            'Add a custom HTTP header to every request (may be repeated). '
            'Format: "Name: Value". '
            'Example: -H "Authorization: Bearer eyJhbG..." -H "X-API-Key: secret"'
        ),
    )
    parser.add_argument(
        "--auth-user",
        default=None,
        metavar="USER",
        help="Username for HTTP Basic / Digest authentication.",
    )
    parser.add_argument(
        "--auth-pass",
        default=None,
        metavar="PASS",
        help="Password for HTTP Basic / Digest authentication (pair with --auth-user).",
    )

    # ── Finding filters ─────────────────────────────────────────────────────────
    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER,
        default=None,
        metavar="LEVEL",
        help=f"Only report findings at or above this severity ({', '.join(SEVERITY_ORDER)}).",
    )
    parser.add_argument(
        "--min-confidence",
        choices=CONFIDENCE_ORDER,
        default=None,
        metavar="LEVEL",
        help=(
            f"Only report findings at or above this confidence ({', '.join(CONFIDENCE_ORDER)}). "
            "Use 'firm' to hide heuristic hits that need manual verification."
        ),
    )
    parser.add_argument(
        "--suppress",
        default=None,
        metavar="FILE",
        help="YAML file of suppression rules for known false positives (see suppress.example.yaml).",
    )

    # ── Output ──────────────────────────────────────────────────────────────────
    parser.add_argument(
        "--output", "-o",
        default=None,
        metavar="FILE",
        help="Output file for the scan report (.json, .sarif, .md, .html, or .pdf). If omitted, terminal output only.",
    )
    parser.add_argument(
        "--incremental",
        action="store_true",
        default=False,
        help=(
            "Reuse a recent cached crawl for this target/scope instead of re-crawling. "
            "The crawl is cached after each run; a changed target or scope invalidates it."
        ),
    )
    parser.add_argument(
        "--cache-file",
        default=None,
        metavar="FILE",
        help="Path to the crawl cache file (default: .vortex_crawl_cache.json).",
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Maximum age of a crawl cache entry to reuse, in seconds (default: 86400).",
    )
    parser.add_argument(
        "--group-endpoints",
        action="store_true",
        default=False,
        help=(
            "Collapse structurally-identical endpoints (same path + parameter names) "
            "to one representative before fuzzing, to speed up large scans."
        ),
    )
    parser.add_argument(
        "--github-repo",
        default=None,
        metavar="OWNER/REPO",
        help="Create a GitHub issue per finding (needs GITHUB_TOKEN in the environment).",
    )
    parser.add_argument(
        "--jira-url",
        default=None,
        metavar="URL",
        help="Jira base URL for issue export (needs --jira-user, --jira-project, JIRA_API_TOKEN).",
    )
    parser.add_argument(
        "--jira-user",
        default=None,
        metavar="EMAIL",
        help="Jira account email for API auth (pair with --jira-url).",
    )
    parser.add_argument(
        "--jira-project",
        default=None,
        metavar="KEY",
        help="Jira project key for created issues (e.g. SEC).",
    )
    parser.add_argument(
        "--issue-min-severity",
        choices=SEVERITY_ORDER,
        default="high",
        help="Minimum severity to export as a tracker issue. Default: high.",
    )
    parser.add_argument(
        "--webhook",
        default=None,
        metavar="URL",
        help=(
            "POST a scan summary (severity counts + finding titles/URLs, no evidence) to this "
            "URL when the scan finishes. Sent without the target's cookies, auth headers, or proxy."
        ),
    )
    parser.add_argument(
        "--webhook-format",
        choices=WEBHOOK_FORMATS,
        default="json",
        help="Webhook body: 'json' (structured summary) or 'slack' (incoming-webhook text). Default: json.",
    )
    parser.add_argument(
        "--disable-anomaly-detection",
        action="store_true",
        default=False,
        help=(
            "Disable statistical anomaly detection (unusual response sizes, latencies, headers). "
            "Anomaly findings are INFORMATIONAL and intended for manual review. "
            "Default: enabled."
        ),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable verbose DEBUG logging.",
    )

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# Module selection
# ─────────────────────────────────────────────────────────────────────────────


def _resolve_modules(modules_arg: str) -> List[str]:
    """
    Parse the ``--modules`` CLI argument and return a validated list of
    module name strings.

    Parameters
    ----------
    modules_arg : str
        The raw ``--modules`` value (e.g. ``"all"``, ``"xss_check,sqli_check"``).

    Returns
    -------
    list[str]
        Ordered list of module name keys present in :data:`MODULE_REGISTRY`.

    Raises
    ------
    SystemExit
        If an unknown module name is provided.
    """
    if modules_arg.strip().lower() == "all":
        # port_scan is opt-in (noisy, legally distinct network activity) and is
        # enabled explicitly via --port-scan / --ports, never by "all".
        return [m for m in MODULE_REGISTRY.keys() if m not in _OPT_IN_MODULES]

    requested = [m.strip() for m in modules_arg.split(",") if m.strip()]
    unknown = [m for m in requested if m not in MODULE_REGISTRY]
    if unknown:
        print(
            f"[ERROR] Unknown module(s): {unknown}. "
            f"Available: {list(MODULE_REGISTRY.keys())}",
            file=sys.stderr,
        )
        sys.exit(1)

    return requested


def _parse_port_list(raw: Optional[str]) -> Optional[List[int]]:
    """
    Parse a ``--ports`` value into a sorted, de-duplicated list of ints.

    Accepts comma-separated single ports and ``lo-hi`` ranges, e.g.
    ``"22,80,8000-8100"``. Returns ``None`` when ``raw`` is empty (meaning
    "use the curated default list"). Exits with an error on malformed input or
    out-of-range (1–65535) ports.
    """
    if not raw or not raw.strip():
        return None

    ports: set = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            if "-" in token:
                lo_s, hi_s = token.split("-", 1)
                lo, hi = int(lo_s), int(hi_s)
                if lo > hi:
                    lo, hi = hi, lo
                rng = range(lo, hi + 1)
            else:
                p = int(token)
                rng = range(p, p + 1)
        except ValueError:
            print(f"[ERROR] Invalid --ports token: {token!r}", file=sys.stderr)
            sys.exit(1)
        for p in rng:
            if not (1 <= p <= 65535):
                print(f"[ERROR] Port out of range (1-65535): {p}", file=sys.stderr)
                sys.exit(1)
            ports.add(p)

    return sorted(ports)


def _parse_custom_headers(raw_headers: Optional[List[str]]) -> Dict[str, str]:
    """
    Parse a list of ``"Name: Value"`` header strings into a dict.

    Accepts the list produced by ``argparse`` ``append`` action from repeated
    ``--header`` / ``-H`` flags.  Malformed entries (no colon, empty name) are
    logged and skipped.

    Parameters
    ----------
    raw_headers : list[str] | None
        Raw header strings, e.g. ``["Authorization: Bearer tok", "X-Key: abc"]``.

    Returns
    -------
    dict[str, str]
        Header name → value mapping ready to pass as ``auth_headers`` to
        :class:`~core.requester.Requester`.
    """
    if not raw_headers:
        return {}

    result: Dict[str, str] = {}
    for raw in raw_headers:
        if ":" not in raw:
            logger.warning(
                "--header: Skipping malformed header (no colon): %r", raw
            )
            continue
        name, _, value = raw.partition(":")
        name = name.strip()
        if not name:
            logger.warning(
                "--header: Skipping header with empty name: %r", raw
            )
            continue
        result[name] = value.strip()
    return result

# ─────────────────────────────────────────────────────────────────────────────
# Scan orchestrator
# ─────────────────────────────────────────────────────────────────────────────


def run_scan(args: argparse.Namespace) -> int:
    """
    Execute the full scan workflow.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    int
        Exit code: 0 = success, 1 = scan error, 2 = findings detected
        (useful for CI/CD pipelines that treat vulnerabilities as build failures).
    """
    # Bootstrap the console from --theme / VORTEX_THEME so even config-load
    # warnings are themed; re-resolved below once config.yaml ui.theme is known.
    try:
        theme, no_color = _resolve_theme(args)
    except ThemeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    console = build_console(theme, no_color=no_color)
    _configure_logging(args.verbose, console)

    # Validate filters before scanning so a typo doesn't waste a full scan.
    try:
        finding_filter = FindingFilter(
            min_severity=getattr(args, "min_severity", None),
            min_confidence=getattr(args, "min_confidence", None),
            rules=load_suppression_rules(args.suppress) if getattr(args, "suppress", None) else None,
        )
    except FilterConfigError as exc:
        logger.error("Invalid finding filter: %s", exc)
        return 1

    webhook = getattr(args, "webhook", None)
    if webhook and urlsplit(webhook).scheme not in ("http", "https"):
        logger.error("--webhook must be an http:// or https:// URL.")
        return 1

    # ── Load configuration ─────────────────────────────────────────────────
    config = _load_config(args.config)

    # ── Layer profile + env overrides onto config, then validate ──────────
    # Precedence: CLI flag > VORTEX_* env > --profile > config.yaml > default.
    try:
        if getattr(args, "profile", None):
            apply_profile(config, args.profile)
        apply_env_overrides(config)
        validate_config(config)
    except ConfigError as exc:
        logger.error("Configuration error: %s", exc)
        return 1

    # config.yaml ui.theme now has a say (under --theme and VORTEX_THEME).
    try:
        resolved_theme, resolved_no_color = _resolve_theme(args, config)
    except ThemeError as exc:
        logger.error("%s", exc)
        return 1
    if (resolved_theme.name, resolved_no_color) != (theme.name, no_color):
        theme, no_color = resolved_theme, resolved_no_color
        console = build_console(theme, no_color=no_color)
        _configure_logging(args.verbose, console)

    req_cfg = config.get("requester", {})
    crawler_cfg = config.get("crawler", {})
    scope_cfg = config.get("scope", {})

    # ── Apply CLI overrides ────────────────────────────────────────────────
    max_depth: int = (
        args.max_depth if args.max_depth is not None
        else int(crawler_cfg.get("max_depth", 3))
    )
    rate_limit_rps: float = (
        args.rate_limit if args.rate_limit is not None
        else float(req_cfg.get("rate_limit_rps", 5))
    )
    verify_ssl: bool = not args.insecure
    proxy: Optional[str] = args.proxy or req_cfg.get("proxy")

    # Thread count precedence: --concurrency > --threads > config/profile/env > 10.
    _threads_default = int(req_cfg.get("concurrency", 10))
    threads: int = max(1, (
        args.concurrency if args.concurrency is not None
        else args.threads if args.threads is not None
        else _threads_default
    ))

    # --timeout overrides config.yaml value.
    timeout: int = (
        args.timeout if args.timeout is not None
        else int(req_cfg.get("timeout", 10))
    )

    max_endpoints: Optional[int] = args.max_endpoints  # --max-endpoints

    if getattr(args, "recon_only", False):
        selected_modules = _resolve_modules("tech_detect,dir_fuzzer,param_fuzzer")
    else:
        selected_modules = _resolve_modules(args.modules)

    # --port-scan / --ports opt the host-scoped port scanner in (it is never
    # part of "all"). --ports implies --port-scan.
    port_scan_enabled = bool(getattr(args, "port_scan", False) or getattr(args, "ports", None))
    if port_scan_enabled and "port_scan" not in selected_modules:
        selected_modules.append("port_scan")

    ui.banner(console, theme, __version__)
    ui.scan_header(
        console,
        theme,
        args.target,
        {
            "Modules": f"{len(selected_modules)} selected {theme.glyphs.dash} "
                       + ", ".join(selected_modules),
            "Depth": max_depth,
            "Threads": threads,
            "Rate": f"{rate_limit_rps:g} req/s" if rate_limit_rps else "unlimited",
            "Timeout": f"{timeout}s",
            "SSL verify": "on" if verify_ssl else "off (--insecure)",
            "Endpoint cap": max_endpoints if max_endpoints else "none",
        },
    )

    # ── Initialise shared Requester ────────────────────────────────────────
    # Resolve auth CLI args.
    auth_headers: Dict[str, str] = _parse_custom_headers(args.header)
    http_auth: Optional[Tuple[str, str]] = (
        (args.auth_user, args.auth_pass)
        if args.auth_user and args.auth_pass
        else None
    )
    if args.auth_user and not args.auth_pass:
        logger.warning(
            "--auth-user supplied without --auth-pass — HTTP auth will not be configured."
        )

    requester = Requester(
        timeout=timeout,
        user_agent=str(req_cfg.get("user_agent", "VortexDAST/1.0")),
        rate_limit_rps=rate_limit_rps,
        verify_ssl=verify_ssl,
        proxy=proxy,
        max_retries=int(req_cfg.get("max_retries", 3)),
        max_workers=threads,
        cookies=args.cookie,
        auth_headers=auth_headers or None,
        http_auth=http_auth,
    )

    scan_start = time.monotonic()

    # Explicit initialisation – avoids dir() anti-pattern in reporting block.
    crawl_result: Optional[CrawlResult] = None
    endpoints: List[CrawledEndpoint] = []
    all_findings: List[Finding] = []

    try:
        # ── Phase 1: Crawl (live spinner) ──────────────────────────────────
        # The concurrent crawler manages its own thread pool internally.
        # We still wrap it in a daemon thread so we can show a Rich spinner
        # while it runs — reading crawl_result.endpoints is safe under the GIL.
        crawler = Crawler(
            requester=requester,
            max_depth=max_depth,
            max_workers=threads,
            max_endpoints=max_endpoints,
        )

        _crawl_exc: List[BaseException] = []

        def _do_crawl() -> None:
            nonlocal crawl_result
            try:
                crawl_result = crawler.crawl(
                    seed_url=args.target,
                    scope_config=scope_cfg,
                )
            except BaseException as exc:  # noqa: BLE001
                _crawl_exc.append(exc)

        # ── Incremental scan: try a cached crawl before spidering ─────────
        _cache_path = args.cache_file or crawl_cache.DEFAULT_CACHE_PATH
        _cache_key = crawl_cache.cache_key(
            args.target,
            {"max_depth": max_depth, "max_endpoints": max_endpoints, "scope": scope_cfg},
        )
        if args.incremental:
            _ttl = args.cache_ttl if args.cache_ttl is not None else crawl_cache.DEFAULT_TTL_SECONDS
            cached = crawl_cache.load_cache(_cache_path, _cache_key, ttl_seconds=_ttl)
            if cached is not None:
                crawl_result = cached
                ui.status(
                    console, theme, "ok",
                    f"Reusing cached crawl — {len(cached.endpoints)} endpoint(s)",
                    "(--incremental)",
                )

        if crawl_result is None:
            crawl_thread = threading.Thread(target=_do_crawl, daemon=True)

            ui.phase(console, theme, 1, "Crawling", f"max depth {max_depth}")

            with Progress(
                SpinnerColumn(spinner_name=theme.spinner, style=theme.style("vortex.accent")),
                TextColumn("{task.description}"),
                console=console,
                transient=True,
            ) as crawl_progress:
                crawl_task = crawl_progress.add_task(
                    f"  [vortex.muted]{args.target}[/vortex.muted]",
                    total=None,  # indeterminate – we don't know the URL count upfront
                )
                crawl_thread.start()

                while crawl_thread.is_alive():
                    discovered = len(crawl_result.endpoints) if crawl_result else 0
                    crawl_progress.update(
                        crawl_task,
                        description=(
                            f"  [vortex.muted]{args.target}[/vortex.muted]  "
                            f"[vortex.value]{discovered}[/vortex.value]"
                            f"[vortex.muted] URL(s) found…[/vortex.muted]"
                        ),
                    )
                    time.sleep(0.25)

                crawl_thread.join()

            # Re-raise any exception from the crawl thread.
            if _crawl_exc:
                raise _crawl_exc[0]

            if crawl_result is None:
                raise RuntimeError("Crawl produced no result — unexpected state.")

            # Persist the fresh crawl so a later --incremental run can reuse it.
            crawl_cache.save_cache(_cache_path, _cache_key, crawl_result)

        ui.status(
            console, theme, "ok", "Crawl complete",
            f"{len(crawl_result.endpoints)} endpoint(s) {theme.glyphs.bullet} "
            f"{crawl_result.total_forms} form(s) {theme.glyphs.bullet} "
            f"{len(crawl_result.failed_urls)} failed",
        )

        if not crawl_result.endpoints:
            logger.warning("No endpoints were crawled. Check target URL and network connectivity.")

        # ── Phase 2: Dynamic crawl (optional) ─────────────────────────────
        if args.dynamic:
            ui.status(
                console, theme, "warn",
                "Dynamic Playwright crawl requested",
                "not yet implemented in this phase",
            )

        # ── Endpoint list ─────────────────────────────────────────────────
        # max_endpoints is now enforced inside Crawler — no post-crawl slice.
        endpoints = crawl_result.endpoints

        # ── Optional: collapse structurally-identical endpoints ───────────
        if args.group_endpoints and endpoints:
            grouping = group_endpoints(endpoints)
            if grouping.collapsed > 0:
                ui.status(
                    console, theme, "group",
                    f"Grouped endpoints — {len(endpoints)} {theme.glyphs.arrow} "
                    f"{grouping.groups} distinct attack surface(s)",
                    f"({grouping.collapsed} collapsed)",
                )
            endpoints = grouping.representatives

        # ── Host-level anchor for port_scan ───────────────────────────────
        # port_scan operates on the target *host*, not on crawled pages. If the
        # crawl produced no endpoint for the seed host (non-HTML landing page,
        # auth wall, JSON API, …), inject a synthetic seed endpoint so the scan
        # still runs against the reachable host rather than silently skipping.
        if port_scan_enabled:
            seed_host = urlsplit(args.target).hostname
            have_seed_host = any(
                urlsplit(ep.url).hostname == seed_host for ep in endpoints
            )
            if seed_host and not have_seed_host:
                endpoints = list(endpoints) + [
                    CrawledEndpoint(url=args.target, status_code=0, depth=0)
                ]

        # ── Phase 3 & 4: Run scanner modules (live progress bar) ──────────
        # Build module instances.  XSSCheckModule accepts a use_threads kwarg
        # to tune its internal concurrency based on the --threads setting.
        def _make_module(name: str) -> BaseScannerModule:
            """Instantiate a module class, forwarding thread-count when applicable."""
            cls = MODULE_REGISTRY[name]
            if name == "xss_check":
                return cls(requester, use_threads=threads > 1)  # type: ignore[call-arg]
            if name == "port_scan":
                inst = cls(requester)
                inst.connect_timeout = float(getattr(args, "port_scan_timeout", 1.5))  # type: ignore[attr-defined]
                inst.max_port_workers = max(1, threads)  # type: ignore[attr-defined]
                ports = _parse_port_list(getattr(args, "ports", None))
                if ports:
                    inst.ports = ports  # type: ignore[attr-defined]
                return inst
            return cls(requester)

        module_instances: List[BaseScannerModule] = [
            _make_module(name) for name in selected_modules
        ]

        total_probes = len(module_instances) * len(endpoints)
        console.print()
        ui.phase(
            console, theme, 2, "Fuzzing",
            f"{len(module_instances)} module(s) x {len(endpoints)} endpoint(s) "
            f"= {total_probes} probe(s)",
        )

        with _make_fuzz_progress(console, theme) as fuzz_progress:
            for module in module_instances:
                task_id = fuzz_progress.add_task(
                    description=(
                        f"[vortex.module]{module.name:<20}[/vortex.module]"
                        f"[vortex.muted]waiting…[/vortex.muted]"
                    ),
                    total=len(endpoints),
                )

                module_findings: List[Finding] = []
                # Lock protecting appends to module_findings across threads.
                _findings_lock = threading.Lock()

                def _probe(
                    ep: "CrawledEndpoint",
                    _mod: BaseScannerModule = module,
                ) -> Tuple[str, List[Finding]]:
                    """Probe one endpoint; return (url, findings) for progress tracking."""
                    return ep.url, _mod.run(ep)

                with ThreadPoolExecutor(
                    max_workers=threads,
                    thread_name_prefix="vdast-fuzz",
                ) as fuzz_pool:
                    future_map = {
                        fuzz_pool.submit(_probe, ep): ep
                        for ep in endpoints
                    }

                    for future in as_completed(future_map):
                        ep = future_map[future]
                        display_url = (
                            ep.url[:70] + "…" if len(ep.url) > 70 else ep.url
                        )
                        try:
                            _url, found = future.result()
                            with _findings_lock:
                                module_findings.extend(found)
                        except Exception as exc:
                            # Isolated per-endpoint — other futures continue.
                            logger.error(
                                "Module %s raised an exception on %s: %s",
                                module.name, ep.url, exc,
                                exc_info=args.verbose,
                            )
                        finally:
                            fuzz_progress.update(
                                task_id,
                                description=(
                                    f"[vortex.module]{module.name:<20}[/vortex.module]"
                                    f"[vortex.muted]{display_url}[/vortex.muted]"
                                ),
                            )
                            fuzz_progress.advance(task_id)

                # Mark task complete with a summary label.
                _found_style = "vortex.success" if module_findings else "vortex.muted"
                fuzz_progress.update(
                    task_id,
                    description=(
                        f"[vortex.module]{module.name:<20}[/vortex.module]"
                        f"[{_found_style}]{len(module_findings)} finding(s)[/{_found_style}]"
                    ),
                )

                # The progress row already shows this; keep the log for -v only
                # and escape the module name so it isn't read as Rich markup.
                logger.debug(
                    "module %s produced %d finding(s)",
                    module.name,
                    len(module_findings),
                )
                all_findings.extend(module_findings)

        # ── Phase 4: Statistical anomaly detection ─────────────────────────────
        if not args.disable_anomaly_detection and endpoints:
            try:
                urls = [ep.url for ep in endpoints]
                features, valid_urls = _collect_response_features(requester, urls)
                if features:  # Only run detector if we have features
                    anomaly_findings = _anomaly_findings(features, valid_urls)
                    if anomaly_findings:
                        ui.status(
                            console, theme, "info",
                            f"{'anomaly':<20}{len(anomaly_findings)} finding(s)",
                            "statistical outliers, informational",
                        )
                        all_findings.extend(anomaly_findings)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Anomaly detection failed: %s", exc)

    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
    finally:
        requester.close()

    scan_duration = time.monotonic() - scan_start

    # ── Phase 5: Reporting ─────────────────────────────────────────────────
    scan_meta: Dict[str, Any] = {
        "scan_duration_s": f"{scan_duration:.2f}",
        "endpoints_crawled": len(crawl_result.endpoints) if crawl_result is not None else 0,
        "endpoints_scanned": len(endpoints),
        "modules_run": ", ".join(selected_modules),
        "max_depth": max_depth,
        "threads": threads,
        "timeout_s": timeout,
        "rate_limit_rps": rate_limit_rps,
        "ssl_verify": verify_ssl,
        "anomaly_detection": not args.disable_anomaly_detection,
    }

    if requester.throttle_events:
        scan_meta["throttle_events"] = requester.throttle_events
        logger.warning(
            "Target throttled %d request(s). Results may be incomplete — consider a lower --rate-limit.",
            requester.throttle_events,
        )

    kept_findings, dropped = finding_filter.apply(Reporter.deduplicate_findings(all_findings))
    if dropped:
        scan_meta["findings_filtered_out"] = len(dropped)
        logger.info("Filtered out %d finding(s) via severity/confidence/suppression rules.", len(dropped))
        for finding, reason in dropped:
            logger.debug("  filtered: %s @ %s (%s)", finding.title, finding.url, reason)

    reporter = Reporter(
        findings=kept_findings,
        target=args.target,
        scan_meta=scan_meta,
        console=console,
        deduplicate=False,
        theme=theme,
    )

    reporter.print_terminal_summary()

    if args.output:
        reporter.save(args.output)

    # Exit 2 = HIGH/CRITICAL findings, for CI pipelines that gate on results.
    exit_code = 2 if any(f.severity.value in ("critical", "high") for f in kept_findings) else 0

    if webhook:
        send_webhook(
            webhook,
            build_payload(kept_findings, args.target, args.webhook_format, exit_code, scan_meta),
        )

    _export_issues(args, kept_findings, console, theme)

    return exit_code


def _export_issues(
    args: argparse.Namespace,
    findings: List[Finding],
    console: Console,
    theme: Optional[VortexTheme] = None,
) -> None:
    """Create GitHub / Jira issues for findings, if a tracker is configured."""
    if not (args.github_repo or args.jira_url):
        return

    th = theme or get_theme()

    from core import issue_tracker  # noqa: PLC0415 — only needed when exporting

    if args.github_repo:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            logger.error("--github-repo set but GITHUB_TOKEN is not in the environment.")
        else:
            session = issue_tracker.github_session(token)
            res = issue_tracker.export_to_github(
                session, args.github_repo, findings, args.issue_min_severity
            )
            ui.status(
                console, th, "ok",
                f"GitHub: created {res.total_created} issue(s)",
                f"skipped {res.skipped} {th.glyphs.bullet} failed {res.failed}",
            )

    if args.jira_url:
        token = os.environ.get("JIRA_API_TOKEN")
        if not (args.jira_user and args.jira_project and token):
            logger.error(
                "--jira-url needs --jira-user, --jira-project, and JIRA_API_TOKEN in the environment."
            )
        else:
            session = issue_tracker.jira_session(args.jira_user, token)
            res = issue_tracker.export_to_jira(
                session, args.jira_url, args.jira_project, findings, args.issue_min_severity
            )
            ui.status(
                console, th, "ok",
                f"Jira: created {res.total_created} issue(s)",
                f"failed {res.failed}",
            )


# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    """
    Primary entrypoint for the ``vortex`` / ``vortexdast`` CLI commands.

    Registered as a ``console_scripts`` entrypoint in ``pyproject.toml``
    and ``setup.py`` so that after ``pip install -e .`` the commands
    ``vortex`` and ``vortexdast`` are available directly in the terminal.

    Returns
    -------
    int
        Exit code propagated to the shell:
          0 – Scan completed, no HIGH/CRITICAL findings (or --list-modules).
          1 – Fatal error during scan initialisation.
          2 – Scan completed with HIGH or CRITICAL findings (CI/CD sentinel).
    """
    parser = _build_parser()
    args = parser.parse_args()

    # Listing commands run before config.yaml is read, so the theme comes from
    # --theme / VORTEX_THEME only.
    try:
        theme, no_color = _resolve_theme(args)
    except ThemeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    # ── --list-themes: preview every palette and exit ──────────────────────
    if args.list_themes:
        ui.theme_table(build_console(theme, no_color=no_color), theme)
        return 0

    # ── --list-modules: print registry table and exit immediately ──────────
    if args.list_modules:
        _print_module_table(build_console(theme, no_color=no_color), theme)
        return 0

    # ── Validate that --target is provided for actual scans ───────────────
    if not args.target:
        parser.error(
            "argument --target/-u is required when not using --list-modules / --list-themes."
        )

    return run_scan(args)


if __name__ == "__main__":
    sys.exit(main())
