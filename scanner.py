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
5.  Run the :class:`~core.crawler.Crawler` to build the attack surface.
6.  Sequentially execute each selected scanner module against every endpoint.
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

    # or equivalently:
    vortexdast -u https://target.example.com

Module names
------------
``headers_audit``, ``xss_check``, ``sqli_check``, ``ssrf_check``, or ``all``.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Type

import yaml
from rich.console import Console
from rich.logging import RichHandler

# Project-root path manipulation so the script runs from the repo root.
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.crawler import Crawler, CrawlResult
from core.reporter import Reporter
from core.requester import Requester
from modules.base import BaseScannerModule, Finding
from modules.headers_audit import HeadersAuditModule
from modules.xss_check import XSSCheckModule
from modules.sqli_check import SQLiCheckModule
from modules.ssrf_check import SSRFCheckModule

# ─────────────────────────────────────────────────────────────────────────────
# Module registry
# ─────────────────────────────────────────────────────────────────────────────

#: Maps CLI module names → module classes.
MODULE_REGISTRY: Dict[str, Type[BaseScannerModule]] = {
    "headers_audit": HeadersAuditModule,
    "xss_check":     XSSCheckModule,
    "sqli_check":    SQLiCheckModule,
    "ssrf_check":    SSRFCheckModule,
}

_DEFAULT_CONFIG_PATH = os.path.join(_ROOT, "config.yaml")

# ─────────────────────────────────────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────────────────────────────────────


def _configure_logging(verbose: bool) -> None:
    """Configure structured logging with RichHandler for prettier output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                rich_tracebacks=True,
                markup=True,
                show_path=False,
            )
        ],
    )


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
            "  vortex -u http://testphp.vulnweb.com\n"
            "  vortex -u https://app.local -k -m xss_check,sqli_check\n"
            "  vortex -u http://target.com --max-depth 2 -o results.json\n"
            "  vortex -u http://target.com --modules all --rate-limit 20 -t 20\n"
            "  vortex -u http://target.com --max-endpoints 10 -t 5 --rate-limit 10\n"
            "  vortexdast -u http://target.com --dynamic --verbose\n"
        ),
    )

    # ── Required ─────────────────────────────────────────────────────────────
    parser.add_argument(
        "--target", "-u",
        required=True,
        metavar="URL",
        help="Target base URL to scan (required). Example: https://target.example.com",
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
            f"Available: {', '.join(MODULE_REGISTRY.keys())}. "
            "Default: all"
        ),
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
        default=10,
        metavar="N",
        help=(
            "Number of concurrent worker threads used by scanner modules. "
            "Higher values reduce wall-clock time for probe-heavy modules (XSS, SQLi, SSRF). "
            "Default: 10. Recommended range: 5–20."
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

    # ── Output ────────────────────────────────────────────────────────────────
    parser.add_argument(
        "--output", "-o",
        default=None,
        metavar="FILE",
        help="Output file for the scan report (.json or .md). If omitted, terminal output only.",
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
        return list(MODULE_REGISTRY.keys())

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
    console = Console()
    _configure_logging(args.verbose)

    # ── Load configuration ─────────────────────────────────────────────────
    config = _load_config(args.config)
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
    threads: int = max(1, args.threads)          # --threads / -t
    max_endpoints: Optional[int] = args.max_endpoints  # --max-endpoints

    selected_modules = _resolve_modules(args.modules)

    logger.info("Target : [bold cyan]%s[/bold cyan]", args.target)
    logger.info("Modules: %s", ", ".join(selected_modules))
    logger.info(
        "Depth: %d | RPS: %.1f | Threads: %d | SSL verify: %s%s",
        max_depth, rate_limit_rps, threads, verify_ssl,
        f" | Endpoint cap: {max_endpoints}" if max_endpoints else "",
    )

    # ── Initialise shared Requester ────────────────────────────────────────
    requester = Requester(
        timeout=int(req_cfg.get("timeout", 10)),
        user_agent=str(req_cfg.get("user_agent", "VortexDAST/1.0")),
        rate_limit_rps=rate_limit_rps,
        verify_ssl=verify_ssl,
        proxy=proxy,
        max_retries=int(req_cfg.get("max_retries", 3)),
        max_workers=threads,
    )

    scan_start = time.monotonic()
    all_findings: List[Finding] = []

    try:
        # ── Phase 1: Crawl ─────────────────────────────────────────────────
        logger.info("Starting BFS crawl…")
        crawler = Crawler(requester=requester, max_depth=max_depth)
        crawl_result: CrawlResult = crawler.crawl(
            seed_url=args.target,
            scope_config=scope_cfg,
        )
        logger.info(
            "Crawl complete: [bold]%d[/bold] endpoints, [bold]%d[/bold] forms, "
            "[bold]%d[/bold] failed",
            len(crawl_result.endpoints),
            crawl_result.total_forms,
            len(crawl_result.failed_urls),
        )

        if not crawl_result.endpoints:
            logger.warning("No endpoints were crawled. Check target URL and network connectivity.")

        # ── Phase 2: Dynamic crawl (optional) ─────────────────────────────
        if args.dynamic:
            logger.info(
                "[yellow]Dynamic Playwright crawl requested — "
                "not yet implemented in this phase.[/yellow]"
            )

        # ── Endpoint cap (--max-endpoints) ────────────────────────────────
        endpoints = crawl_result.endpoints
        if max_endpoints and len(endpoints) > max_endpoints:
            logger.info(
                "--max-endpoints %d: capping crawl surface from %d → %d endpoints.",
                max_endpoints, len(endpoints), max_endpoints,
            )
            endpoints = endpoints[:max_endpoints]

        # ── Phase 3 & 4: Run scanner modules ──────────────────────────────
        # Build module instances.  Modules that accept extra kwargs (e.g.
        # XSSCheckModule) receive the thread-count so they can tune their
        # internal concurrency accordingly.
        def _make_module(name: str) -> BaseScannerModule:
            cls = MODULE_REGISTRY[name]
            if name == "xss_check":
                return cls(requester, use_threads=threads > 1)  # type: ignore[call-arg]
            return cls(requester)

        module_instances: List[BaseScannerModule] = [
            _make_module(name) for name in selected_modules
        ]

        for module in module_instances:
            logger.info("Running module: [bold]%s[/bold]", module.name)
            module_findings: List[Finding] = []

            for endpoint in endpoints:
                try:
                    found = module.run(endpoint)
                    module_findings.extend(found)
                except Exception as exc:
                    logger.error(
                        "Module %s raised an exception on %s: %s",
                        module.name, endpoint.url, exc,
                        exc_info=args.verbose,
                    )

            logger.info(
                "  [%s] → [bold]%d[/bold] finding(s)",
                module.name,
                len(module_findings),
            )
            all_findings.extend(module_findings)

    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
    finally:
        requester.close()

    scan_duration = time.monotonic() - scan_start

    # ── Phase 5: Reporting ─────────────────────────────────────────────────
    scan_meta = {
        "scan_duration_s": f"{scan_duration:.2f}",
        "endpoints_crawled": len(crawl_result.endpoints) if "crawl_result" in dir() else 0,
        "endpoints_scanned": len(endpoints) if "endpoints" in dir() else 0,
        "modules_run": ", ".join(selected_modules),
        "max_depth": max_depth,
        "threads": threads,
        "rate_limit_rps": rate_limit_rps,
        "ssl_verify": verify_ssl,
    }

    reporter = Reporter(
        findings=all_findings,
        target=args.target,
        scan_meta=scan_meta,
        console=console,
    )

    reporter.print_terminal_summary()

    if args.output:
        reporter.save(args.output)

    # Exit code semantics for CI/CD pipelines.
    if any(
        f.severity.value in ("critical", "high")
        for f in all_findings
        if isinstance(f.severity, type(f.severity))
    ):
        return 2  # Findings of HIGH or CRITICAL severity detected.
    return 0


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
          0 – Scan completed, no HIGH/CRITICAL findings.
          1 – Fatal error during scan initialisation.
          2 – Scan completed with HIGH or CRITICAL findings (CI/CD sentinel).
    """
    parser = _build_parser()
    args = parser.parse_args()
    return run_scan(args)


if __name__ == "__main__":
    sys.exit(main())
