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

import html
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

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
        deduplicate: bool = True,
    ) -> None:
        self.raw_findings = findings
        self.findings = self.deduplicate_findings(findings) if deduplicate else findings
        self.target = target
        self.scan_meta = scan_meta or {}
        self._console = console or Console()
        self._timestamp = datetime.now(timezone.utc).isoformat()

        # Pre-group findings by severity for reuse across render methods.
        self._by_severity: Dict[str, List[Finding]] = {s: [] for s in _SEVERITY_ORDER}
        for finding in self.findings:
            sev = finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity)
            if sev in self._by_severity:
                self._by_severity[sev].append(finding)

    @staticmethod
    def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
        """
        Deduplicate findings by grouping on (module, url, parameter, finding_title).

        Multiple probe hits for the same flaw are merged into a single Finding
        containing all observed evidence variants.

        Parameters
        ----------
        findings : list[Finding]
            Raw list of findings aggregated from scanner modules.

        Returns
        -------
        list[Finding]
            Deduplicated list of findings.
        """
        if not findings:
            return []

        grouped: Dict[Tuple[str, str, str, str], List[Finding]] = {}
        order: List[Tuple[str, str, str, str]] = []

        for finding in findings:
            module = str(finding.extra.get("module", "")) if isinstance(finding.extra, dict) else ""
            url = finding.url or ""
            param = finding.parameter or ""
            title = finding.title or ""
            key = (module, url, param, title)

            if key not in grouped:
                grouped[key] = []
                order.append(key)
            grouped[key].append(finding)

        deduped: List[Finding] = []

        for key in order:
            group = grouped[key]
            if len(group) == 1:
                deduped.append(group[0])
                continue

            first = group[0]

            # Collect unique evidence snippets
            evidences: List[str] = []
            seen_evidence = set()
            for f in group:
                ev = f.evidence.strip() if f.evidence else ""
                if ev and ev not in seen_evidence:
                    seen_evidence.add(ev)
                    evidences.append(ev)

            merged_evidence = "\n---\n".join(evidences) if evidences else first.evidence

            # Collect unique payloads
            payloads: List[str] = []
            seen_payloads = set()
            for f in group:
                pl = f.payload.strip() if f.payload else ""
                if pl and pl not in seen_payloads:
                    seen_payloads.add(pl)
                    payloads.append(pl)

            # Pick highest severity level
            best_sev = first.severity
            for f in group:
                f_sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
                b_sev = best_sev.value if isinstance(best_sev, Severity) else str(best_sev)
                if f_sev in _SEVERITY_ORDER and b_sev in _SEVERITY_ORDER:
                    if _SEVERITY_ORDER.index(f_sev) < _SEVERITY_ORDER.index(b_sev):
                        best_sev = f.severity

            # Pick highest CVSS score & vector
            best_cvss_score = first.cvss_score
            best_cvss_vector = first.cvss_vector
            for f in group:
                if f.cvss_score is not None:
                    if best_cvss_score is None or f.cvss_score > best_cvss_score:
                        best_cvss_score = f.cvss_score
                        best_cvss_vector = f.cvss_vector

            extra_meta: Dict[str, Any] = dict(first.extra) if isinstance(first.extra, dict) else {}
            extra_meta["merged_count"] = len(group)
            if len(evidences) > 1:
                extra_meta["evidence_variants"] = evidences
            if len(payloads) > 1:
                extra_meta["payload_variants"] = payloads

            merged_finding = Finding(
                id=first.id,
                title=first.title,
                severity=best_sev,
                url=first.url,
                parameter=first.parameter,
                payload=first.payload if first.payload else (payloads[0] if payloads else None),
                evidence=merged_evidence,
                description=first.description,
                remediation=first.remediation,
                extra=extra_meta,
                cvss_vector=best_cvss_vector,
                cvss_score=best_cvss_score,
            )
            deduped.append(merged_finding)

        return deduped

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

    def save_html(self, path: str) -> None:
        """
        Write an interactive single-page HTML report to ``path``.

        Embeds CSS and minimal vanilla JS directly in the HTML file for full
        air-gapped offline support without CDN dependencies.

        Parameters
        ----------
        path : str
            Destination file path (should end with ``.html`` or ``.htm``).
        """
        _ensure_dir(path)
        content = self._render_html()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        self._console.print(f"[green]✔[/green] HTML report saved → [cyan]{path}[/cyan]")

    def save(self, path: str) -> None:
        """
        Dispatch to the appropriate save method based on file extension.

        Supports ``.json``, ``.md`` / ``.markdown``, and ``.html`` / ``.htm`` extensions.
        Falls back to JSON for unrecognised extensions.

        Parameters
        ----------
        path : str
            Output file path.
        """
        ext = os.path.splitext(path)[-1].lower()
        if ext in {".md", ".markdown"}:
            self.save_markdown(path)
        elif ext in {".html", ".htm"}:
            self.save_html(path)
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

    def _render_html(self) -> str:
        """Produce the full single-page interactive HTML report as a string."""
        total_findings = len(self.findings)
        c_crit = len(self._by_severity["critical"])
        c_high = len(self._by_severity["high"])
        c_med = len(self._by_severity["medium"])
        c_low = len(self._by_severity["low"])
        c_info = len(self._by_severity["informational"])

        if total_findings > 0:
            p_crit = (c_crit / total_findings) * 100
            p_high = (c_high / total_findings) * 100
            p_med = (c_med / total_findings) * 100
            p_low = (c_low / total_findings) * 100
            p_info = (c_info / total_findings) * 100
        else:
            p_crit = p_high = p_med = p_low = p_info = 0.0

        escaped_target = html.escape(self.target)
        escaped_timestamp = html.escape(self._timestamp)

        meta_pills_html = []
        if self.scan_meta:
            for k, v in self.scan_meta.items():
                label = html.escape(k.replace("_", " ").title())
                val = html.escape(str(v))
                meta_pills_html.append(f'<span class="meta-pill"><strong>{label}:</strong> {val}</span>')
        meta_pills_str = " ".join(meta_pills_html)

        cards_html_list = []
        for sev in _SEVERITY_ORDER:
            for finding in self._by_severity[sev]:
                f_sev = sev
                f_id = html.escape(finding.id)
                f_title = html.escape(finding.title)
                f_url = html.escape(finding.url)
                f_param = html.escape(finding.parameter) if finding.parameter else None
                f_payload = html.escape(finding.payload) if finding.payload else None
                f_evidence = html.escape(finding.evidence) if finding.evidence else None
                f_desc = html.escape(finding.description) if finding.description else None
                f_rem = html.escape(finding.remediation) if finding.remediation else None
                f_module = html.escape(str(finding.extra.get("module", "N/A"))) if isinstance(finding.extra, dict) else "N/A"

                if finding.cvss_score is not None:
                    f_cvss_score = str(finding.cvss_score)
                else:
                    f_cvss_score = _CVSS_RANGES[sev]["score"]

                if finding.cvss_vector:
                    f_cvss_vector = html.escape(finding.cvss_vector)
                else:
                    f_cvss_vector = html.escape(_CVSS_RANGES[sev]["example_vector"])

                merged_count = finding.extra.get("merged_count", 1) if isinstance(finding.extra, dict) else 1

                haystack = f"{finding.id} {finding.title} {finding.url} {finding.parameter or ''} {finding.description or ''} {finding.evidence or ''} {f_module}".lower()
                escaped_haystack = html.escape(haystack)

                card_html = f"""
        <div class="finding-card" data-severity="{f_sev}" data-search-text="{escaped_haystack}">
          <div class="card-header" onclick="toggleCard(this)">
            <div class="header-left">
              <span class="badge {f_sev}">{f_sev.upper()}</span>
              <span class="finding-title">{f_title}</span>
              <span class="finding-url-short">{f_url}</span>
            </div>
            <div class="header-right">
              <span class="cvss-pill">CVSS {f_cvss_score}</span>
              <span class="chevron">▼</span>
            </div>
          </div>
          <div class="card-body">
            <table class="details-table">
              <tr><td class="label">Finding ID</td><td><code>{f_id}</code></td></tr>
              <tr><td class="label">Module</td><td><code>{f_module}</code></td></tr>
              <tr><td class="label">Target URL</td><td><code>{f_url}</code></td></tr>
              {f'<tr><td class="label">Parameter</td><td><code>{f_param}</code></td></tr>' if f_param else ''}
              {f'<tr><td class="label">Payload</td><td><code>{f_payload}</code></td></tr>' if f_payload else ''}
              <tr><td class="label">CVSS v3.1</td><td><strong>{f_cvss_score}</strong> <code>{f_cvss_vector}</code></td></tr>
              {f'<tr><td class="label">Merged Hits</td><td><span class="badge informational">{merged_count} probe hits merged</span></td></tr>' if merged_count > 1 else ''}
            </table>
            {f'<div class="section-title">Description</div><p class="description-text">{f_desc}</p>' if f_desc else ''}
            {f'<div class="section-title">Observed Evidence</div><pre><code>{f_evidence}</code></pre>' if f_evidence else ''}
            {f'<div class="remediation-box"><div class="section-title" style="margin-top:0;">Remediation Guidance</div><p>{f_rem}</p></div>' if f_rem else ''}
          </div>
        </div>"""
                cards_html_list.append(card_html)

        cards_str = "\n".join(cards_html_list)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VortexDAST Security Scan Report — {escaped_target}</title>
  <style>
    :root {{
      --bg-color: #0b0f19;
      --card-bg: #161f30;
      --card-border: #233248;
      --text-main: #e2e8f0;
      --text-muted: #94a3b8;
      --accent: #3b82f6;
      --sev-critical: #ef4444;
      --sev-critical-bg: rgba(239, 68, 68, 0.15);
      --sev-high: #f97316;
      --sev-high-bg: rgba(249, 115, 22, 0.15);
      --sev-medium: #eab308;
      --sev-medium-bg: rgba(234, 179, 8, 0.15);
      --sev-low: #06b6d4;
      --sev-low-bg: rgba(6, 182, 212, 0.15);
      --sev-info: #64748b;
      --sev-info-bg: rgba(100, 116, 139, 0.15);
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg-color);
      color: var(--text-main);
      line-height: 1.6;
      padding: 2rem 1rem;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header {{
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 2rem;
      margin-bottom: 2rem;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
    }}
    .header-title {{
      font-size: 1.85rem;
      font-weight: 700;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}
    .header-title span.logo {{ color: var(--accent); }}
    .header-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem 1.5rem;
      margin-top: 1rem;
      font-size: 0.9rem;
      color: var(--text-muted);
    }}
    .meta-pill {{
      background: #0f172a;
      border: 1px solid var(--card-border);
      padding: 0.25rem 0.65rem;
      border-radius: 6px;
      font-size: 0.825rem;
    }}
    .meta-pill strong {{ color: var(--text-main); }}

    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .metric-card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 1.25rem;
      text-align: center;
      transition: transform 0.2s, border-color 0.2s;
    }}
    .metric-card:hover {{ transform: translateY(-2px); }}
    .metric-card.total {{ border-top: 4px solid var(--accent); }}
    .metric-card.critical {{ border-top: 4px solid var(--sev-critical); }}
    .metric-card.high {{ border-top: 4px solid var(--sev-high); }}
    .metric-card.medium {{ border-top: 4px solid var(--sev-medium); }}
    .metric-card.low {{ border-top: 4px solid var(--sev-low); }}
    .metric-card.informational {{ border-top: 4px solid var(--sev-info); }}

    .metric-value {{
      font-size: 2.2rem;
      font-weight: 800;
      line-height: 1.2;
    }}
    .metric-card.total .metric-value {{ color: var(--accent); }}
    .metric-card.critical .metric-value {{ color: var(--sev-critical); }}
    .metric-card.high .metric-value {{ color: var(--sev-high); }}
    .metric-card.medium .metric-value {{ color: var(--sev-medium); }}
    .metric-card.low .metric-value {{ color: var(--sev-low); }}
    .metric-card.informational .metric-value {{ color: var(--sev-info); }}
    .metric-label {{
      font-size: 0.825rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-top: 0.25rem;
    }}

    .breakdown-section {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 1.5rem;
      margin-bottom: 2rem;
    }}
    .section-header {{
      font-size: 1.1rem;
      font-weight: 600;
      margin-bottom: 1rem;
      color: #ffffff;
    }}
    .progress-bar-stacked {{
      display: flex;
      height: 14px;
      border-radius: 7px;
      overflow: hidden;
      background: #0f172a;
      margin-bottom: 1.25rem;
    }}
    .bar-segment {{ height: 100%; transition: width 0.3s; }}
    .bar-segment.critical {{ background: var(--sev-critical); }}
    .bar-segment.high {{ background: var(--sev-high); }}
    .bar-segment.medium {{ background: var(--sev-medium); }}
    .bar-segment.low {{ background: var(--sev-low); }}
    .bar-segment.informational {{ background: var(--sev-info); }}

    .breakdown-legend {{
      display: flex;
      flex-wrap: wrap;
      gap: 1.5rem;
      font-size: 0.875rem;
    }}
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
    .dot.critical {{ background: var(--sev-critical); }}
    .dot.high {{ background: var(--sev-high); }}
    .dot.medium {{ background: var(--sev-medium); }}
    .dot.low {{ background: var(--sev-low); }}
    .dot.informational {{ background: var(--sev-info); }}

    .toolbar {{
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1.5rem;
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 1rem 1.25rem;
    }}
    .search-box {{
      flex: 1;
      min-width: 260px;
      position: relative;
    }}
    .search-box input {{
      width: 100%;
      background: #0f172a;
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 0.6rem 1rem 0.6rem 2.2rem;
      color: var(--text-main);
      font-size: 0.9rem;
      outline: none;
    }}
    .search-box input:focus {{ border-color: var(--accent); }}
    .search-icon {{
      position: absolute;
      left: 0.75rem;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-muted);
    }}

    .filter-buttons {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
    .btn-filter {{
      background: #0f172a;
      border: 1px solid var(--card-border);
      color: var(--text-muted);
      padding: 0.45rem 0.85rem;
      border-radius: 6px;
      font-size: 0.85rem;
      cursor: pointer;
      transition: all 0.2s;
    }}
    .btn-filter:hover {{ color: var(--text-main); border-color: var(--text-muted); }}
    .btn-filter.active {{ background: var(--accent); color: #ffffff; border-color: var(--accent); }}

    .controls-right {{ display: flex; gap: 0.5rem; }}
    .btn-toggle-all {{
      background: transparent;
      border: 1px solid var(--card-border);
      color: var(--text-muted);
      padding: 0.45rem 0.85rem;
      border-radius: 6px;
      font-size: 0.85rem;
      cursor: pointer;
    }}
    .btn-toggle-all:hover {{ color: var(--text-main); border-color: var(--text-muted); }}

    .status-text {{ font-size: 0.875rem; color: var(--text-muted); margin-bottom: 1rem; }}

    .finding-card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      margin-bottom: 1rem;
      overflow: hidden;
      transition: border-color 0.2s;
    }}
    .finding-card:hover {{ border-color: #3b82f6; }}
    .card-header {{
      padding: 1rem 1.25rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
      user-select: none;
      background: rgba(255, 255, 255, 0.02);
      gap: 1rem;
    }}
    .header-left {{ display: flex; align-items: center; gap: 0.85rem; flex-wrap: wrap; }}
    .badge {{
      padding: 0.25rem 0.65rem;
      border-radius: 4px;
      font-weight: 700;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .badge.critical {{ background: var(--sev-critical-bg); color: var(--sev-critical); border: 1px solid var(--sev-critical); }}
    .badge.high {{ background: var(--sev-high-bg); color: var(--sev-high); border: 1px solid var(--sev-high); }}
    .badge.medium {{ background: var(--sev-medium-bg); color: var(--sev-medium); border: 1px solid var(--sev-medium); }}
    .badge.low {{ background: var(--sev-low-bg); color: var(--sev-low); border: 1px solid var(--sev-low); }}
    .badge.informational {{ background: var(--sev-info-bg); color: var(--sev-info); border: 1px solid var(--sev-info); }}

    .finding-title {{ font-size: 1rem; font-weight: 600; color: #ffffff; }}
    .finding-url-short {{ font-size: 0.85rem; color: var(--text-muted); font-family: monospace; }}
    .header-right {{ display: flex; align-items: center; gap: 0.75rem; }}
    .cvss-pill {{
      font-size: 0.8rem;
      font-weight: 600;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      background: #0f172a;
      border: 1px solid var(--card-border);
      color: var(--text-main);
    }}
    .chevron {{ color: var(--text-muted); transition: transform 0.2s; font-size: 0.8rem; }}
    .finding-card.open .chevron {{ transform: rotate(180deg); }}

    .card-body {{
      display: none;
      padding: 1.25rem;
      border-top: 1px solid var(--card-border);
      background: #0f172a;
    }}
    .finding-card.open .card-body {{ display: block; }}

    .details-table {{ width: 100%; border-collapse: collapse; margin-bottom: 1rem; font-size: 0.875rem; }}
    .details-table td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }}
    .details-table td.label {{ width: 160px; font-weight: 600; color: var(--text-muted); }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      background: rgba(255, 255, 255, 0.06);
      padding: 0.15rem 0.4rem;
      border-radius: 4px;
      font-size: 0.85rem;
      color: #93c5fd;
    }}
    .section-title {{
      font-weight: 600;
      font-size: 0.85rem;
      margin: 1rem 0 0.5rem 0;
      color: #ffffff;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .description-text {{ font-size: 0.9rem; color: var(--text-main); }}
    pre {{
      background: #060911;
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 0.85rem;
      overflow-x: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      color: #a7f3d0;
      line-height: 1.4;
      white-space: pre-wrap;
    }}
    .remediation-box {{
      background: rgba(59, 130, 246, 0.08);
      border-left: 4px solid var(--accent);
      border-radius: 4px;
      padding: 0.85rem 1rem;
      margin-top: 1rem;
      font-size: 0.9rem;
    }}
    .empty-state {{
      text-align: center;
      padding: 3rem;
      background: var(--card-bg);
      border: 1px dashed var(--card-border);
      border-radius: 10px;
      color: var(--text-muted);
    }}
    .footer {{ text-align: center; margin-top: 3rem; font-size: 0.85rem; color: var(--text-muted); }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="header-title">
        <span class="logo">⚡</span> VortexDAST Security Scan Report
      </div>
      <div class="header-meta">
        <span class="meta-pill"><strong>Target:</strong> {escaped_target}</span>
        <span class="meta-pill"><strong>Scan Time:</strong> {escaped_timestamp}</span>
        {meta_pills_str}
      </div>
    </div>

    <!-- Executive Metric Cards -->
    <div class="metrics-grid">
      <div class="metric-card total">
        <div class="metric-value">{total_findings}</div>
        <div class="metric-label">Total Findings</div>
      </div>
      <div class="metric-card critical">
        <div class="metric-value">{c_crit}</div>
        <div class="metric-label">Critical</div>
      </div>
      <div class="metric-card high">
        <div class="metric-value">{c_high}</div>
        <div class="metric-label">High</div>
      </div>
      <div class="metric-card medium">
        <div class="metric-value">{c_med}</div>
        <div class="metric-label">Medium</div>
      </div>
      <div class="metric-card low">
        <div class="metric-value">{c_low}</div>
        <div class="metric-label">Low</div>
      </div>
      <div class="metric-card informational">
        <div class="metric-value">{c_info}</div>
        <div class="metric-label">Informational</div>
      </div>
    </div>

    <!-- Severity Breakdown Bar -->
    <div class="breakdown-section">
      <div class="section-header">Severity Breakdown</div>
      <div class="progress-bar-stacked">
        <div class="bar-segment critical" style="width: {p_crit:.1f}%;"></div>
        <div class="bar-segment high" style="width: {p_high:.1f}%;"></div>
        <div class="bar-segment medium" style="width: {p_med:.1f}%;"></div>
        <div class="bar-segment low" style="width: {p_low:.1f}%;"></div>
        <div class="bar-segment informational" style="width: {p_info:.1f}%;"></div>
      </div>
      <div class="breakdown-legend">
        <div class="legend-item"><span class="dot critical"></span> Critical ({c_crit})</div>
        <div class="legend-item"><span class="dot high"></span> High ({c_high})</div>
        <div class="legend-item"><span class="dot medium"></span> Medium ({c_med})</div>
        <div class="legend-item"><span class="dot low"></span> Low ({c_low})</div>
        <div class="legend-item"><span class="dot informational"></span> Info ({c_info})</div>
      </div>
    </div>

    <!-- Toolbar & Search/Filter -->
    <div class="toolbar">
      <div class="search-box">
        <span class="search-icon">🔍</span>
        <input type="text" id="search-input" placeholder="Search findings by keyword, URL, param, module, evidence...">
      </div>
      <div class="filter-buttons">
        <button class="btn-filter active" onclick="setSeverityFilter('all', this)">All ({total_findings})</button>
        <button class="btn-filter" onclick="setSeverityFilter('critical', this)">Critical ({c_crit})</button>
        <button class="btn-filter" onclick="setSeverityFilter('high', this)">High ({c_high})</button>
        <button class="btn-filter" onclick="setSeverityFilter('medium', this)">Medium ({c_med})</button>
        <button class="btn-filter" onclick="setSeverityFilter('low', this)">Low ({c_low})</button>
        <button class="btn-filter" onclick="setSeverityFilter('informational', this)">Info ({c_info})</button>
      </div>
      <div class="controls-right">
        <button class="btn-toggle-all" onclick="toggleAll(true)">Expand All</button>
        <button class="btn-toggle-all" onclick="toggleAll(false)">Collapse All</button>
      </div>
    </div>

    <div class="status-text">
      Showing <span id="visible-count">{total_findings}</span> of {total_findings} findings
    </div>

    <!-- Finding Cards List -->
    <div id="findings-list">
      {cards_str}
    </div>

    <div id="no-findings" class="empty-state" style="display: none;">
      No findings match your selected filter criteria.
    </div>

    <div class="footer">
      Generated by <strong>VortexDAST</strong> — Dynamic Application Security Testing Framework
    </div>
  </div>

  <script>
    let currentSeverityFilter = 'all';

    function toggleCard(headerEl) {{
      const card = headerEl.closest('.finding-card');
      if (card) card.classList.toggle('open');
    }}

    function toggleAll(expand) {{
      const cards = document.querySelectorAll('.finding-card');
      cards.forEach(card => {{
        if (card.style.display !== 'none') {{
          if (expand) card.classList.add('open');
          else card.classList.remove('open');
        }}
      }});
    }}

    function setSeverityFilter(sev, btn) {{
      currentSeverityFilter = sev;
      document.querySelectorAll('.btn-filter').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filterFindings();
    }}

    function filterFindings() {{
      const searchInput = document.getElementById('search-input');
      const searchVal = searchInput ? searchInput.value.toLowerCase().trim() : '';
      const cards = document.querySelectorAll('.finding-card');
      let visibleCount = 0;

      cards.forEach(card => {{
        const cardSev = card.getAttribute('data-severity');
        const searchText = card.getAttribute('data-search-text') || '';

        const matchesSev = (currentSeverityFilter === 'all' || cardSev === currentSeverityFilter);
        const matchesSearch = (!searchVal || searchText.includes(searchVal));

        if (matchesSev && matchesSearch) {{
          card.style.display = 'block';
          visibleCount++;
        }} else {{
          card.style.display = 'none';
        }}
      }});

      const visibleEl = document.getElementById('visible-count');
      if (visibleEl) visibleEl.textContent = visibleCount;

      const noFindingsEl = document.getElementById('no-findings');
      if (noFindingsEl) {{
        noFindingsEl.style.display = (visibleCount === 0 && cards.length > 0) ? 'block' : 'none';
      }}
    }}

    document.addEventListener('DOMContentLoaded', () => {{
      const searchInput = document.getElementById('search-input');
      if (searchInput) {{
        searchInput.addEventListener('input', filterFindings);
      }}
    }});
  </script>
</body>
</html>"""



# ─────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────────────────────


def _ensure_dir(path: str) -> None:
    """Create parent directories for ``path`` if they do not already exist."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
