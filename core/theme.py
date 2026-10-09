"""
VortexDAST – core/theme.py
────────────────────────────────────────────────────────────────────────────
Terminal colour themes for the CLI.

Every colour the CLI prints goes through a *semantic style token* (for example
``vortex.accent`` or ``sev.critical``) rather than a hard-coded colour name.
A :class:`VortexTheme` maps those tokens to concrete Rich styles, so switching
``--theme`` recolours the whole UI — scan header, progress bars, module table
and the findings dashboard — without touching any render code.

The default theme is :data:`DEFAULT_THEME` (``minimal``): near-monochrome,
no banner, thin borders. Colour is spent only where it carries meaning
(severity, success/warning/error). Richer palettes are opt-in.

Usage
-----
::

    from core.theme import build_console, get_theme

    theme = get_theme("neon")
    console = build_console(theme)
    console.print("[vortex.accent]hello[/vortex.accent]")
    console.print(theme.text("CRITICAL", "sev.critical"))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from rich import box
from rich.console import Console
from rich.text import Text
from rich.theme import Theme

# ─────────────────────────────────────────────────────────────────────────────
# Token vocabulary
# ─────────────────────────────────────────────────────────────────────────────

#: Every style token a theme must define. Render code may only use these.
STYLE_TOKENS: Tuple[str, ...] = (
    "vortex.brand",      # product name in banners / panel titles
    "vortex.title",      # table + panel titles, section headings
    "vortex.phase",      # "Phase 1 — Crawling" labels
    "vortex.accent",     # the one highlight colour (target URL, key numbers)
    "vortex.value",      # inline counts and measured values
    "vortex.label",      # key names in key/value lines
    "vortex.muted",      # secondary detail, hints, footnotes
    "vortex.border",     # table + panel borders
    "vortex.header",     # table header row
    "vortex.module",     # scanner module identifiers
    "vortex.url",        # URLs in tables
    "vortex.param",      # parameter names
    "vortex.success",    # completed steps
    "vortex.warning",    # recoverable problems
    "vortex.error",      # failures
    "vortex.info",       # neutral notices
    "sev.critical",
    "sev.high",
    "sev.medium",
    "sev.low",
    "sev.informational",
)

#: Severity value → style token. Mirrors ``modules.base.Severity`` values.
SEVERITY_TOKENS: Dict[str, str] = {
    "critical": "sev.critical",
    "high": "sev.high",
    "medium": "sev.medium",
    "low": "sev.low",
    "informational": "sev.informational",
}


# ─────────────────────────────────────────────────────────────────────────────
# Glyph sets
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Glyphs:
    """Single-character marks used to prefix status lines."""

    ok: str = "✓"
    warn: str = "!"
    error: str = "✗"
    info: str = "·"
    arrow: str = "→"
    bullet: str = "•"
    group: str = "⇄"
    bar_full: str = "█"
    bar_empty: str = "·"
    dash: str = "—"


#: ASCII-only glyphs for dumb terminals, CI logs and the ``mono`` theme.
ASCII_GLYPHS = Glyphs(
    ok="+",
    warn="!",
    error="x",
    info="-",
    arrow="->",
    bullet="*",
    group="<>",
    bar_full="#",
    bar_empty=".",
    dash="-",
)


# ─────────────────────────────────────────────────────────────────────────────
# Theme object
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class VortexTheme:
    """
    A named palette plus the layout choices that go with it.

    Attributes
    ----------
    name : str
        CLI identifier, as passed to ``--theme``.
    description : str
        One-line summary shown by ``--list-themes``.
    styles : dict[str, str]
        Mapping of every token in :data:`STYLE_TOKENS` to a Rich style string.
    table_box, panel_box : rich.box.Box
        Border styles for tables and panels.
    spinner : str
        Rich spinner name used by the crawl / fuzz progress displays.
    banner : bool
        Whether to draw the large ASCII wordmark at scan start. ``False`` keeps
        the start-up output to a couple of lines.
    glyphs : Glyphs
        Status-line marks.
    """

    name: str
    description: str
    styles: Dict[str, str]
    table_box: box.Box = box.SIMPLE
    panel_box: box.Box = box.ROUNDED
    spinner: str = "line"
    banner: bool = False
    glyphs: Glyphs = field(default_factory=Glyphs)

    # ── Lookups ──────────────────────────────────────────────────────────
    def style(self, token: str) -> str:
        """Return the Rich style string for ``token`` (``""`` when unknown)."""
        return self.styles.get(token, "")

    def severity_style(self, severity: str) -> str:
        """Return the Rich style string for a severity value such as ``"high"``."""
        return self.style(SEVERITY_TOKENS.get(str(severity).lower(), "vortex.muted"))

    def text(self, content: str, token: str) -> Text:
        """Build a :class:`rich.text.Text` already styled with ``token``."""
        return Text(content, style=self.style(token))

    def rich_theme(self) -> Theme:
        """Return a :class:`rich.theme.Theme` so markup tags resolve by token."""
        return Theme(self.styles, inherit=True)


# ─────────────────────────────────────────────────────────────────────────────
# Theme definitions
# ─────────────────────────────────────────────────────────────────────────────


def _palette(**overrides: str) -> Dict[str, str]:
    """Build a complete token map from the minimal base plus ``overrides``."""
    merged = dict(_MINIMAL_STYLES)
    merged.update(overrides)
    return merged


# The baseline: structure carried by weight (bold/dim), colour reserved for
# severity and pass/fail. Every other theme is expressed as a delta from here.
_MINIMAL_STYLES: Dict[str, str] = {
    "vortex.brand": "bold",
    "vortex.title": "bold",
    "vortex.phase": "bold",
    "vortex.accent": "bold",
    "vortex.value": "bold",
    "vortex.label": "dim",
    "vortex.muted": "dim",
    "vortex.border": "dim",
    "vortex.header": "bold",
    "vortex.module": "default",
    "vortex.url": "dim",
    "vortex.param": "italic",
    "vortex.success": "green",
    "vortex.warning": "yellow",
    "vortex.error": "bold red",
    "vortex.info": "dim",
    "sev.critical": "bold red",
    "sev.high": "red",
    "sev.medium": "yellow",
    "sev.low": "cyan",
    "sev.informational": "dim",
}

_THEMES: Dict[str, VortexTheme] = {}


def _register(theme: VortexTheme) -> VortexTheme:
    _THEMES[theme.name] = theme
    return theme


_register(
    VortexTheme(
        name="minimal",
        description="Default. Near-monochrome; colour only for severity and status.",
        styles=dict(_MINIMAL_STYLES),
        table_box=box.SIMPLE,
        panel_box=box.MINIMAL,
        spinner="line",
        banner=False,
    )
)

_register(
    VortexTheme(
        name="mono",
        description="No colour at all, ASCII borders and marks. Best for CI logs.",
        styles=_palette(
            **{
                "vortex.header": "bold underline",
                "vortex.url": "default",
                "vortex.success": "bold",
                "vortex.warning": "bold",
                "vortex.error": "bold reverse",
                "vortex.info": "dim",
                "sev.critical": "bold reverse",
                "sev.high": "bold",
                "sev.medium": "default",
                "sev.low": "dim",
                "sev.informational": "dim",
            }
        ),
        table_box=box.ASCII,
        panel_box=box.ASCII,
        spinner="line",
        banner=False,
        glyphs=ASCII_GLYPHS,
    )
)

_register(
    VortexTheme(
        name="vortex",
        description="Brand palette: violet headings, cyan accents, rounded frames.",
        styles=_palette(
            **{
                "vortex.brand": "bold #a855f7",
                "vortex.title": "bold #c084fc",
                "vortex.phase": "bold #22d3ee",
                "vortex.accent": "bold #22d3ee",
                "vortex.value": "bold #e2e8f0",
                "vortex.label": "#7c8aa5",
                "vortex.muted": "#64748b",
                "vortex.border": "#6d28d9",
                "vortex.header": "bold #c084fc",
                "vortex.module": "#38bdf8",
                "vortex.url": "#94a3b8",
                "vortex.param": "italic #a5b4fc",
                "vortex.success": "bold #34d399",
                "vortex.warning": "bold #fbbf24",
                "vortex.error": "bold #fb7185",
                "vortex.info": "#7dd3fc",
                "sev.critical": "bold #f43f5e",
                "sev.high": "bold #fb923c",
                "sev.medium": "#fbbf24",
                "sev.low": "#38bdf8",
                "sev.informational": "#64748b",
            }
        ),
        table_box=box.ROUNDED,
        panel_box=box.ROUNDED,
        spinner="dots",
        banner=True,
    )
)

_register(
    VortexTheme(
        name="neon",
        description="High-contrast cyberpunk: magenta, electric cyan, heavy frames.",
        styles=_palette(
            **{
                "vortex.brand": "bold bright_magenta",
                "vortex.title": "bold bright_magenta",
                "vortex.phase": "bold bright_cyan",
                "vortex.accent": "bold bright_cyan",
                "vortex.value": "bold bright_white",
                "vortex.label": "magenta",
                "vortex.muted": "bright_black",
                "vortex.border": "bright_magenta",
                "vortex.header": "bold bright_white on #3b0764",
                "vortex.module": "bold bright_green",
                "vortex.url": "cyan",
                "vortex.param": "italic bright_yellow",
                "vortex.success": "bold bright_green",
                "vortex.warning": "bold bright_yellow",
                "vortex.error": "bold bright_red",
                "vortex.info": "bright_cyan",
                "sev.critical": "bold bright_white on red",
                "sev.high": "bold bright_red",
                "sev.medium": "bold bright_yellow",
                "sev.low": "bold bright_cyan",
                "sev.informational": "bright_black",
            }
        ),
        table_box=box.HEAVY_HEAD,
        panel_box=box.HEAVY,
        spinner="dots2",
        banner=True,
    )
)

_register(
    VortexTheme(
        name="matrix",
        description="Single-hue green terminal, from dim to phosphor bright.",
        styles=_palette(
            **{
                "vortex.brand": "bold bright_green",
                "vortex.title": "bold green",
                "vortex.phase": "bold bright_green",
                "vortex.accent": "bold bright_green",
                "vortex.value": "bright_green",
                "vortex.label": "#2f6f3f",
                "vortex.muted": "#2f6f3f",
                "vortex.border": "#166534",
                "vortex.header": "bold black on green",
                "vortex.module": "green",
                "vortex.url": "#4ade80",
                "vortex.param": "italic #86efac",
                "vortex.success": "bold bright_green",
                "vortex.warning": "bold #bef264",
                "vortex.error": "bold #f87171",
                "vortex.info": "#4ade80",
                "sev.critical": "bold black on bright_green",
                "sev.high": "bold bright_green",
                "sev.medium": "green",
                "sev.low": "#4ade80",
                "sev.informational": "#2f6f3f",
            }
        ),
        table_box=box.SIMPLE_HEAVY,
        panel_box=box.SQUARE,
        spinner="dots12",
        banner=True,
    )
)

_register(
    VortexTheme(
        name="dracula",
        description="Dracula palette: purple, pink and soft cyan on dark.",
        styles=_palette(
            **{
                "vortex.brand": "bold #bd93f9",
                "vortex.title": "bold #ff79c6",
                "vortex.phase": "bold #8be9fd",
                "vortex.accent": "bold #8be9fd",
                "vortex.value": "bold #f8f8f2",
                "vortex.label": "#6272a4",
                "vortex.muted": "#6272a4",
                "vortex.border": "#bd93f9",
                "vortex.header": "bold #f8f8f2",
                "vortex.module": "#50fa7b",
                "vortex.url": "#8be9fd",
                "vortex.param": "italic #f1fa8c",
                "vortex.success": "bold #50fa7b",
                "vortex.warning": "bold #ffb86c",
                "vortex.error": "bold #ff5555",
                "vortex.info": "#8be9fd",
                "sev.critical": "bold #ff5555",
                "sev.high": "bold #ffb86c",
                "sev.medium": "#f1fa8c",
                "sev.low": "#8be9fd",
                "sev.informational": "#6272a4",
            }
        ),
        table_box=box.ROUNDED,
        panel_box=box.ROUNDED,
        spinner="dots",
        banner=True,
    )
)

_register(
    VortexTheme(
        name="nord",
        description="Nord palette: cool arctic blues with muted accents.",
        styles=_palette(
            **{
                "vortex.brand": "bold #88c0d0",
                "vortex.title": "bold #81a1c1",
                "vortex.phase": "bold #8fbcbb",
                "vortex.accent": "bold #88c0d0",
                "vortex.value": "bold #eceff4",
                "vortex.label": "#4c566a",
                "vortex.muted": "#616e88",
                "vortex.border": "#5e81ac",
                "vortex.header": "bold #e5e9f0",
                "vortex.module": "#8fbcbb",
                "vortex.url": "#81a1c1",
                "vortex.param": "italic #b48ead",
                "vortex.success": "bold #a3be8c",
                "vortex.warning": "bold #ebcb8b",
                "vortex.error": "bold #bf616a",
                "vortex.info": "#88c0d0",
                "sev.critical": "bold #bf616a",
                "sev.high": "bold #d08770",
                "sev.medium": "#ebcb8b",
                "sev.low": "#88c0d0",
                "sev.informational": "#616e88",
            }
        ),
        table_box=box.ROUNDED,
        panel_box=box.ROUNDED,
        spinner="dots",
        banner=True,
    )
)

_register(
    VortexTheme(
        name="solarized",
        description="Solarized Dark: low-glare base tones with warm accents.",
        styles=_palette(
            **{
                "vortex.brand": "bold #268bd2",
                "vortex.title": "bold #2aa198",
                "vortex.phase": "bold #268bd2",
                "vortex.accent": "bold #2aa198",
                "vortex.value": "bold #eee8d5",
                "vortex.label": "#586e75",
                "vortex.muted": "#657b83",
                "vortex.border": "#073642",
                "vortex.header": "bold #93a1a1",
                "vortex.module": "#859900",
                "vortex.url": "#839496",
                "vortex.param": "italic #6c71c4",
                "vortex.success": "bold #859900",
                "vortex.warning": "bold #b58900",
                "vortex.error": "bold #dc322f",
                "vortex.info": "#268bd2",
                "sev.critical": "bold #dc322f",
                "sev.high": "bold #cb4b16",
                "sev.medium": "#b58900",
                "sev.low": "#268bd2",
                "sev.informational": "#657b83",
            }
        ),
        table_box=box.HORIZONTALS,
        panel_box=box.ROUNDED,
        spinner="dots",
        banner=True,
    )
)

_register(
    VortexTheme(
        name="gruvbox",
        description="Gruvbox: warm retro earth tones, amber and olive.",
        styles=_palette(
            **{
                "vortex.brand": "bold #fabd2f",
                "vortex.title": "bold #d79921",
                "vortex.phase": "bold #83a598",
                "vortex.accent": "bold #fabd2f",
                "vortex.value": "bold #ebdbb2",
                "vortex.label": "#928374",
                "vortex.muted": "#928374",
                "vortex.border": "#504945",
                "vortex.header": "bold #ebdbb2",
                "vortex.module": "#b8bb26",
                "vortex.url": "#83a598",
                "vortex.param": "italic #d3869b",
                "vortex.success": "bold #b8bb26",
                "vortex.warning": "bold #fabd2f",
                "vortex.error": "bold #fb4934",
                "vortex.info": "#83a598",
                "sev.critical": "bold #fb4934",
                "sev.high": "bold #fe8019",
                "sev.medium": "#fabd2f",
                "sev.low": "#83a598",
                "sev.informational": "#928374",
            }
        ),
        table_box=box.HEAVY_HEAD,
        panel_box=box.ROUNDED,
        spinner="dots",
        banner=True,
    )
)

#: Name of the theme used when nothing is configured.
DEFAULT_THEME_NAME = "minimal"

#: Tuple of valid ``--theme`` values, in display order.
THEME_NAMES: Tuple[str, ...] = tuple(_THEMES)


class ThemeError(ValueError):
    """Raised when an unknown theme name is requested."""


def get_theme(name: Optional[str] = None) -> VortexTheme:
    """
    Look up a theme by name.

    Parameters
    ----------
    name : str | None
        Theme identifier (case-insensitive). ``None`` or an empty string
        returns the default theme.

    Raises
    ------
    ThemeError
        If ``name`` is not a registered theme.
    """
    if not name:
        return _THEMES[DEFAULT_THEME_NAME]
    key = str(name).strip().lower()
    if key not in _THEMES:
        raise ThemeError(
            f"unknown theme {name!r}; choose from {', '.join(THEME_NAMES)}"
        )
    return _THEMES[key]


def all_themes() -> List[VortexTheme]:
    """Return every registered theme, in registration order."""
    return list(_THEMES.values())


#: The default theme object.
DEFAULT_THEME = _THEMES[DEFAULT_THEME_NAME]


# ─────────────────────────────────────────────────────────────────────────────
# Console factory
# ─────────────────────────────────────────────────────────────────────────────


def build_console(
    theme: Optional[VortexTheme] = None,
    *,
    no_color: bool = False,
    **console_kwargs: object,
) -> Console:
    """
    Build a :class:`rich.console.Console` wired to ``theme``.

    Token markup (``[vortex.accent]…[/vortex.accent]``) resolves through the
    console's theme stack, so callers never name a raw colour.

    Parameters
    ----------
    theme : VortexTheme | None
        Theme to install. Defaults to :data:`DEFAULT_THEME`.
    no_color : bool
        Strip all colour from the output while keeping layout and weights.
        Honoured on top of whichever theme is active.
    **console_kwargs
        Forwarded verbatim to :class:`~rich.console.Console` (``file``,
        ``width``, ``force_terminal``, …).
    """
    active = theme or DEFAULT_THEME
    return Console(
        theme=active.rich_theme(),
        no_color=no_color or None,
        **console_kwargs,  # type: ignore[arg-type]
    )
