"""
VortexDAST – core/reporter.py
────────────────────────────────────────────────────────────────────────────
Centralised Reporting Engine.

Consumes the structured list of :class:`~modules.base.Finding` objects
produced by all scanner modules and renders them in three output formats:

  1. **JSON** — Machine-readable, CI/CD-friendly report with full metadata.
  2. **Markdown** — Human-readable report with severity summary table, CVSS
     score mappings, finding details, and remediation guidance.
  3. **Rich terminal dashboard** — Colour-coded, interactive table printed to
     stdout using the ``rich`` library, grouped by severity.

Usage
-----
::

    reporter = Reporter(findings=all_findings, target=seed_url, scan_meta=meta)
    reporter.print_terminal_summary()
    reporter.save_json("reports/scan_result.json")
    reporter.save_markdown("reports/scan_result.md")
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from modules.base import Finding, Severity

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# CVSS v3.1 base score ranges — used only in the severity-level summary
# table to show a representative score for each bucket. Individual findings
# carry their own calculated :attr:`~modules.base.Finding.cvss_score` and
# :attr:`~modules.base.Finding.cvss_vector`.
_CVSS_RANGES: Dict[str, Dict[str, Any]] = {
    Severity.CRITICAL.value: {
        "range": "9.0 – 10.0",
        "example_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "score": "9.8",
    },
    Severity.HIGH.value: {
        "range": "7.0 – 8.9",
        "example_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "score": "8.1",
    },
    Severity.MEDIUM.value: {
        "range": "4.0 – 6.9",
        "example_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "score": "5.3",
    },
    Severity.LOW.value: {
        "range": "0.1 – 3.9",
        "example_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "score": "3.1",
    },
    Severity.INFORMATIONAL.value: {
        "range": "0.0",
        "example_vector": "N/A",
        "score": "0.0",
    },
}

# Rich colour codes for each severity level.
_SEVERITY_STYLES: Dict[str, str] = {
    Severity.CRITICAL.value:     "bold red",
    Severity.HIGH.value:         "red",
    Severity.MEDIUM.value:       "yellow",
    Severity.LOW.value:          "cyan",
    Severity.INFORMATIONAL.value: "dim",
}

# Canonical severity display order (highest first).
_SEVERITY_ORDER: List[str] = [
    Severity.CRITICAL.value,
    Severity.HIGH.value,
    Severity.MEDIUM.value,
    Severity.LOW.value,
    Severity.INFORMATIONAL.value,
]


# ─────────────────────────────────────────────────────────────────────────────
# Reporter class
# ─────────────────────────────────────────────────────────────────────────────


class Reporter:
    """
    Centralised reporting engine for VortexDAST scan results.

    Parameters
    ----------
    findings : list[Finding]
        All findings aggregated from every scanner module.
    target : str
        The seed URL that was scanned.
    scan_meta : dict | None
        Optional metadata dict included in reports (e.g. scan duration,
        module list, endpoint count).
    console : rich.console.Console | None
        Custom Rich console for testing or output redirection.
    """

    def __init__(
        self,
        findings: List[Finding],
        target: str,
        scan_meta: Optional[Dict[str, Any]] = None,
        console: Optional[Console] = None,
    ) -> None:
        self.findings = findings
        self.target = target
        self.scan_meta = scan_meta or {}
        self._console = console or Console()
        self._timestamp = datetime.now(timezone.utc).isoformat()

        # Pre-group findings by severity for reuse across render methods.
        self._by_severity: Dict[str, List[Finding]] = {s: [] for s in _SEVERITY_ORDER}
        for finding in findings:
            sev = finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity)
            if sev in self._by_severity:
                self._by_severity[sev].append(finding)

    # ─────────────────────────────────────────────────────────────────────────
    # Public output methods
    # ─────────────────────────────────────────────────────────────────────────

    def print_terminal_summary(self) -> None:
        """
        Render a rich colour-coded dashboard to the terminal.

        Displays:
          *  A header panel with scan target and timestamp.
          *  A severity count summary table.
          *  Per-severity finding detail tables.
        """
        c = self._console

        # ── Header banner ─────────────────────────────────────────────────
        c.print()
        c.print(
            Panel(
                f"[bold white]VortexDAST[/bold white] — Scan Report\n"
                f"[dim]Target:[/dim] [bold cyan]{self.target}[/bold cyan]\n"
                f"[dim]Time:  [/dim] [white]{self._timestamp}[/white]\n"
                f"[dim]Total findings: [/dim][bold]{len(self.findings)}[/bold]",
                title="[bold]⚡ VortexDAST[/bold]",
                border_style="bright_blue",
                padding=(1, 4),
            )
        )

        # ── Severity summary table ─────────────────────────────────────────
        summary_table = Table(
            title="Finding Summary",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white",
            border_style="bright_blue",
            padding=(0, 2),
        )
        summary_table.add_column("Severity", style="bold", min_width=16)
        summary_table.add_column("Count", justify="center", min_width=8)
        summary_table.add_column("CVSS v3.1 Score Range", justify="center", min_width=22)

        for sev in _SEVERITY_ORDER:
            count = len(self._by_severity[sev])
            style = _SEVERITY_STYLES[sev]
            cvss_range = _CVSS_RANGES[sev]["range"]
            summary_table.add_row(
                Text(sev.upper(), style=style),
                Text(str(count), style=style if count > 0 else "dim"),
                Text(cvss_range, style="dim"),
            )
        c.print(summary_table)
        c.print()

        # ── Per-severity finding tables ───────────────────────────────────
        for sev in _SEVERITY_ORDER:
            bucket = self._by_severity[sev]
            if not bucket:
                continue

            style = _SEVERITY_STYLES[sev]
            detail_table = Table(
                title=f"[{style}]{sev.upper()} Findings ({len(bucket)})[/{style}]",
                box=box.SIMPLE_HEAVY,
                show_header=True,
                header_style="bold white on grey23",
                border_style=style,
                padding=(0, 1),
                expand=True,
            )
            detail_table.add_column("#", justify="right", min_width=3, style="dim")
            detail_table.add_column("Title", min_width=30)
            detail_table.add_column("URL", min_width=30, overflow="fold")
            detail_table.add_column("Param", min_width=12)
            detail_table.add_column("CVSS", justify="center", min_width=6)
            detail_table.add_column("Module", min_width=14)

            for idx, finding in enumerate(bucket, start=1):
                module_name = finding.extra.get("module", "headers_audit")
                param_display = finding.parameter or "—"
                # Show real per-finding CVSS score if available; fall back to
                # the severity-bucket approximate score.
                if finding.cvss_score is not None:
                    cvss_display = str(finding.cvss_score)
                else:
                    cvss_display = _CVSS_RANGES[sev]["score"]
                detail_table.add_row(
                    str(idx),
                    Text(finding.title, style=style),
                    Text(finding.url, style="link " + finding.url),
                    Text(param_display, style="italic"),
                    Text(cvss_display, style=style),
                    Text(module_name, style="dim"),
                )
            c.print(detail_table)
            c.print()

        # ── Scan metadata footer ──────────────────────────────────────────
        if self.scan_meta:
            meta_lines = [f"[dim]{k}:[/dim] {v}" for k, v in self.scan_meta.items()]
            c.print(Panel("\n".join(meta_lines), title="Scan Metadata", border_style="dim"))
            c.print()

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialise the full scan result as a plain Python dict.

        This is the canonical in-memory representation used by both
        :meth:`save_json` and any future export plugins.
        """
        severity_counts = {s: len(self._by_severity[s]) for s in _SEVERITY_ORDER}

        return {
            "vortexdast_version": "1.0.0",
            "report_timestamp": self._timestamp,
            "target": self.target,
            "scan_metadata": self.scan_meta,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": severity_counts,
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def save_json(self, path: str) -> None:
        """
        Write a structured JSON report to ``path``.

        Creates any necessary parent directories automatically.

        Parameters
        ----------
        path : str
            Destination file path (should end with ``.json``).
        """
        _ensure_dir(path)
        data = self.to_dict()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        self._console.print(f"[green]✔[/green] JSON report saved → [cyan]{path}[/cyan]")

    def save_markdown(self, path: str) -> None:
        """
        Write a human-readable Markdown report to ``path``.

        Creates any necessary parent directories automatically.

        Parameters
        ----------
        path : str
            Destination file path (should end with ``.md``).
        """
        _ensure_dir(path)
        content = self._render_markdown()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        self._console.print(f"[green]✔[/green] Markdown report saved → [cyan]{path}[/cyan]")

    def save(self, path: str) -> None:
        """
        Dispatch to the appropriate save method based on file extension.

        Supports ``.json`` and ``.md`` / ``.markdown`` extensions.
        Falls back to JSON for unrecognised extensions.

        Parameters
        ----------
        path : str
            Output file path.
        """
        ext = os.path.splitext(path)[-1].lower()
        if ext in {".md", ".markdown"}:
            self.save_markdown(path)
        else:
            self.save_json(path)

    # ─────────────────────────────────────────────────────────────────────────
    # Markdown rendering
    # ─────────────────────────────────────────────────────────────────────────

    def _render_markdown(self) -> str:
        """Produce the full Markdown report as a string."""
        lines: List[str] = []

        # ── Title & metadata ──────────────────────────────────────────────
        lines += [
            "# VortexDAST — Security Scan Report",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Target** | `{self.target}` |",
            f"| **Scan Timestamp** | {self._timestamp} |",
            f"| **Total Findings** | {len(self.findings)} |",
        ]

        if self.scan_meta:
            for k, v in self.scan_meta.items():
                lines.append(f"| **{k.replace('_', ' ').title()}** | {v} |")

        lines += [
            "", "---", "",
            "## Executive Summary",
            "",
            "| Severity | Count | CVSS v3.1 Score Range | Representative Vector |",
            "|----------|---------|-----------------------|-----------------------|",
        ]
        for sev in _SEVERITY_ORDER:
            count = len(self._by_severity[sev])
            cvss = _CVSS_RANGES[sev]
            lines.append(
                f"| **{sev.upper()}** | {count} "
                f"| {cvss['range']} "
                f"| `{cvss['example_vector']}` |"
            )

        lines += ["", "---", ""]

        # ── Finding details per severity ──────────────────────────────────
        lines.append("## Detailed Findings")
        lines.append("")

        finding_number = 0
        for sev in _SEVERITY_ORDER:
            bucket = self._by_severity[sev]
            if not bucket:
                continue

            lines += [f"### {sev.upper()} Severity", ""]

            for finding in bucket:
                finding_number += 1
                lines += self._render_finding_md(finding, finding_number)

        # ── Remediation summary ───────────────────────────────────────────
        lines += ["---", "", "## Remediation Summary", ""]
        seen_titles: set = set()
        for sev in _SEVERITY_ORDER:
            for finding in self._by_severity[sev]:
                if finding.title not in seen_titles and finding.remediation:
                    seen_titles.add(finding.title)
                    lines += [
                        f"### {finding.title}",
                        "",
                        finding.remediation,
                        "",
                    ]

        # ── Footer ────────────────────────────────────────────────────────
        lines += [
            "---",
            "",
            "*Report generated by [VortexDAST](https://github.com/vortexdast) — "
            "a lightweight Dynamic Application Security Testing framework.*",
            "",
        ]

        return "\n".join(lines)

    @staticmethod
    def _render_finding_md(finding: Finding, number: int) -> List[str]:
        """Render a single finding as Markdown lines."""
        lines: List[str] = [
            f"#### Finding #{number}: {finding.title}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **ID** | `{finding.id}` |",
            f"| **Severity** | **{finding.severity.value.upper()}** |",
        ]

        # Real CVSS v3.1 data — show score and full vector if available.
        if finding.cvss_score is not None:
            lines.append(f"| **CVSS v3.1 Score** | `{finding.cvss_score}` |")
        if finding.cvss_vector:
            lines.append(f"| **CVSS v3.1 Vector** | `{finding.cvss_vector}` |")

        lines += [
            f"| **URL** | `{finding.url}` |",
        ]

        if finding.parameter:
            lines.append(f"| **Parameter** | `{finding.parameter}` |")
        if finding.payload:
            # Escape pipe characters in payloads to avoid breaking the table.
            safe_payload = finding.payload.replace("|", "&#124;")
            lines.append(f"| **Payload** | `{safe_payload}` |")

        lines += ["", "**Description**", ""]
        lines.append(finding.description or "_No description provided._")

        if finding.evidence:
            lines += ["", "**Evidence**", "", f"```\n{finding.evidence}\n```"]

        if finding.remediation:
            lines += ["", "**Remediation**", ""]
            lines.append(finding.remediation)

        lines += ["", "---", ""]
        return lines


# ─────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────────────────────


def _ensure_dir(path: str) -> None:
    """Create parent directories for ``path`` if they do not already exist."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
