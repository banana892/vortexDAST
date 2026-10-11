"""
VortexDAST – core/ui.py
────────────────────────────────────────────────────────────────────────────
Reusable terminal UI primitives for the CLI.

Every helper here takes an explicit :class:`~core.theme.VortexTheme` and emits
only semantic style tokens, so the look of the whole CLI is decided by the
active theme (see :mod:`core.theme`). The default ``minimal`` theme renders
these as thin, near-monochrome lines; themes with ``banner=True`` get framed
panels and a wordmark.

Pieces
------
``banner``        Large wordmark (suppressed by minimal themes).
``scan_header``   Target + resolved settings block shown before Phase 1.
``phase``         "Phase N — Title" section heading.
``status``        Glyph-prefixed one-line status (ok / warn / error / info).
``severity_bar``  Compact proportional bar of findings by severity.
``theme_table``   ``--list-themes`` output, each row drawn in its own palette.
"""

from __future__ import annotations

from typing import Dict, Mapping, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.theme import VortexTheme, all_themes

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_WORDMARK = """
 █  █ ████ ████ ████ ████ █  █    ███  ████ ████ ████
 █  █ █  █ █  █  ██  ███   ██     █  █ █  █ ███   ██ 
 █  █ █  █ ███   ██  █     ██     █  █ ████   ██  ██ 
  ██  ████ █  █  ██  ████ █  █    ███  █  █ ████  ██
""".strip("\n")

#: Severity order, worst first — matches the reporter's display order.
_SEVERITY_ORDER: Tuple[str, ...] = ("critical", "high", "medium", "low", "informational")

#: Status kind → (glyph attribute, style token).
_STATUS_KINDS: Dict[str, Tuple[str, str]] = {
    "ok": ("ok", "vortex.success"),
    "warn": ("warn", "vortex.warning"),
    "error": ("error", "vortex.error"),
    "info": ("info", "vortex.info"),
    "group": ("group", "vortex.accent"),
}


# ─────────────────────────────────────────────────────────────────────────────
# Blocks
# ─────────────────────────────────────────────────────────────────────────────


def banner(console: Console, theme: VortexTheme, version: str = "") -> None:
    """
    Print the ASCII wordmark, for themes that opt into it.

    Minimal themes (``banner=False``) print nothing at all, keeping start-up
    output to the scan header.
    """
    if not theme.banner:
        return
    console.print()
    console.print(Text(_WORDMARK, style=theme.style("vortex.brand")))
    tagline = "Dynamic Application Security Testing"
    if version:
        tagline = f"{tagline}  {theme.glyphs.bullet}  v{version}"
    console.print(Text(f"   {tagline}", style=theme.style("vortex.muted")))
    console.print()


def scan_header(
    console: Console,
    theme: VortexTheme,
    target: str,
    settings: Mapping[str, object],
) -> None:
    """
    Render the pre-scan block: the target plus the settings actually in effect
    after config, profile, env and CLI flags have been resolved.

    Parameters
    ----------
    settings : Mapping[str, object]
        Ordered key → value pairs, printed as an aligned two-column block.
    """
    label = theme.style("vortex.label")
    value = theme.style("vortex.value")
    muted = theme.style("vortex.muted")

    # One shared label column so "Target" lines up with every setting below it.
    width = max([len("Target")] + [len(str(k)) for k in settings])

    body = Text()
    body.append(f"{'Target'.ljust(width)}  ", style=label)
    body.append(str(target), style=theme.style("vortex.accent"))
    for key, val in settings.items():
        body.append("\n")
        body.append(f"{str(key).ljust(width)}  ", style=label)
        body.append(str(val), style=value if str(val) else muted)

    if theme.banner:
        console.print(
            Panel(
                body,
                title=Text("scan", style=theme.style("vortex.title")),
                title_align="left",
                box=theme.panel_box,
                border_style=theme.style("vortex.border"),
                padding=(0, 2),
            )
        )
    else:
        console.print()
        console.print(body)
    console.print()


def phase(
    console: Console,
    theme: VortexTheme,
    index: int,
    title: str,
    detail: str = "",
) -> None:
    """Print a ``Phase N — Title`` section heading with optional dim detail."""
    line = Text()
    line.append(f"Phase {index} ", style=theme.style("vortex.phase"))
    line.append(f"{theme.glyphs.arrow} ", style=theme.style("vortex.muted"))
    line.append(title, style=theme.style("vortex.phase"))
    if detail:
        line.append(f"   {detail}", style=theme.style("vortex.muted"))
    console.print(line)


def status(
    console: Console,
    theme: VortexTheme,
    kind: str,
    message: str,
    detail: str = "",
) -> None:
    """
    Print one glyph-prefixed status line.

    Parameters
    ----------
    kind : str
        One of ``ok``, ``warn``, ``error``, ``info``, ``group``. Unknown kinds
        fall back to ``info``.
    message : str
        Main text, rendered in the kind's colour.
    detail : str
        Optional trailing text, always muted.
    """
    glyph_attr, token = _STATUS_KINDS.get(kind, _STATUS_KINDS["info"])
    line = Text("  ")
    line.append(f"{getattr(theme.glyphs, glyph_attr)} ", style=theme.style(token))
    line.append(message, style=theme.style("vortex.value"))
    if detail:
        line.append(f"  {detail}", style=theme.style("vortex.muted"))
    console.print(line)


def severity_bar(
    theme: VortexTheme,
    counts: Mapping[str, int],
    width: int = 40,
) -> Text:
    """
    Build a proportional one-line bar of findings by severity, worst first.

    Each severity occupies at least one cell when present, so a lone CRITICAL
    among hundreds of informational findings is still visible. Returns an empty
    :class:`Text` when there are no findings.
    """
    total = sum(max(0, counts.get(sev, 0)) for sev in _SEVERITY_ORDER)
    if total <= 0 or width <= 0:
        return Text()

    present = [sev for sev in _SEVERITY_ORDER if counts.get(sev, 0) > 0]
    # Reserve one cell per present severity, share the rest proportionally.
    spare = max(0, width - len(present))
    cells = {sev: 1 + int(round(spare * counts[sev] / total)) for sev in present}

    # Correct rounding drift so the bar is exactly `width` cells wide.
    drift = width - sum(cells.values())
    if drift and present:
        widest = max(present, key=lambda s: cells[s])
        cells[widest] = max(1, cells[widest] + drift)

    bar = Text()
    for sev in present:
        bar.append(theme.glyphs.bar_full * cells[sev], style=theme.severity_style(sev))
    return bar


def severity_counts_line(theme: VortexTheme, counts: Mapping[str, int]) -> Text:
    """Build a compact ``3 critical · 1 high · 12 low`` legend, worst first."""
    line = Text()
    first = True
    for sev in _SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count <= 0:
            continue
        if not first:
            line.append(f" {theme.glyphs.bullet} ", style=theme.style("vortex.muted"))
        line.append(str(count), style=theme.severity_style(sev))
        line.append(f" {sev}", style=theme.style("vortex.muted"))
        first = False
    return line


def theme_table(console: Console, active: Optional[VortexTheme] = None) -> None:
    """
    Print every available theme, with each row's swatch drawn in that theme's
    own palette so the colours can be compared before committing to one.
    """
    base = active or all_themes()[0]
    table = Table(
        title=Text(f"VortexDAST {base.glyphs.dash} Colour themes", style=base.style("vortex.title")),
        title_justify="left",
        box=base.table_box,
        show_header=True,
        header_style=base.style("vortex.header"),
        border_style=base.style("vortex.border"),
        padding=(0, 1),
    )
    table.add_column("Theme", no_wrap=True, min_width=10)
    table.add_column("Severity palette", no_wrap=True, min_width=34)
    table.add_column("Description", overflow="fold")

    for theme in all_themes():
        swatch = Text()
        for sev in _SEVERITY_ORDER:
            swatch.append(f" {sev[:4].upper()} ", style=theme.severity_style(sev))
            swatch.append(" ")

        name = Text(theme.name, style=theme.style("vortex.accent"))
        if active is not None and theme.name == active.name:
            name.append("  (active)", style=theme.style("vortex.muted"))

        table.add_row(name, swatch, Text(theme.description, style=theme.style("vortex.muted")))

    console.print()
    console.print(table)
    console.print(
        Text("  Select with --theme NAME, config.yaml ui.theme, or VORTEX_THEME.",
             style=base.style("vortex.muted"))
    )
    console.print()
