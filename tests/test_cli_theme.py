"""
VortexDAST – tests/test_cli_theme.py
────────────────────────────────────────────────────────────────────────────
Tests for the terminal theming layer:
  *  core/theme.py   — theme registry, token completeness, console factory
  *  core/ui.py      — banner, scan header, phase/status lines, severity bar
  *  core/profiles.py — ui.theme config validation + VORTEX_THEME env override
  *  scanner.py      — --theme / --no-color / --list-themes wiring
  *  core/reporter.py — themed dashboard rendering

Rendering is asserted against an in-memory console, so no TTY is required.

Run with:
    pytest tests/test_cli_theme.py -v
"""

from __future__ import annotations

import io
import os
import sys
from typing import Dict

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scanner
from core import ui
from core.profiles import ConfigError, apply_env_overrides, validate_config
from core.reporter import Reporter
from core.theme import (
    ASCII_GLYPHS,
    DEFAULT_THEME,
    DEFAULT_THEME_NAME,
    SEVERITY_TOKENS,
    STYLE_TOKENS,
    THEME_NAMES,
    ThemeError,
    all_themes,
    build_console,
    get_theme,
)
from modules.base import Confidence, Finding, Severity


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _capture(theme=None, width: int = 110, **kwargs):
    """Return (console, buffer) pair that renders into memory with colour on."""
    buf = io.StringIO()
    console = build_console(
        theme or DEFAULT_THEME, file=buf, force_terminal=True, width=width, **kwargs
    )
    return console, buf


def _finding(
    title: str = "Reflected XSS",
    severity: Severity = Severity.CRITICAL,
    module: str = "xss_check",
    parameter=None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        url="http://target.local/search",
        parameter=parameter,
        payload="<svg onload=1>",
        evidence="payload echoed",
        description="desc",
        remediation="fix it",
        extra={"module": module},
        cvss_score=9.6,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Theme registry
# ─────────────────────────────────────────────────────────────────────────────


class TestThemeRegistry:
    """Every registered theme must be complete and self-consistent."""

    def test_default_theme_is_registered_and_minimal(self) -> None:
        assert DEFAULT_THEME_NAME == "minimal"
        assert DEFAULT_THEME.name == "minimal"
        assert get_theme() is DEFAULT_THEME
        assert get_theme(None) is DEFAULT_THEME
        assert get_theme("") is DEFAULT_THEME

    def test_more_than_one_theme_is_offered(self) -> None:
        assert len(THEME_NAMES) >= 5
        assert "minimal" in THEME_NAMES

    @pytest.mark.parametrize("name", THEME_NAMES)
    def test_every_theme_defines_every_token(self, name: str) -> None:
        theme = get_theme(name)
        assert set(theme.styles) == set(STYLE_TOKENS), f"{name} token mismatch"
        assert all(theme.style(tok) is not None for tok in STYLE_TOKENS)

    @pytest.mark.parametrize("name", THEME_NAMES)
    def test_every_theme_has_a_description_and_spinner(self, name: str) -> None:
        theme = get_theme(name)
        assert theme.description.strip()
        assert theme.spinner.strip()

    @pytest.mark.parametrize("name", THEME_NAMES)
    def test_every_theme_resolves_every_severity(self, name: str) -> None:
        theme = get_theme(name)
        for severity in SEVERITY_TOKENS:
            assert theme.severity_style(severity) == theme.styles[SEVERITY_TOKENS[severity]]

    def test_lookup_is_case_insensitive_and_trims(self) -> None:
        assert get_theme("  NEON ").name == "neon"

    def test_unknown_theme_raises(self) -> None:
        with pytest.raises(ThemeError) as exc:
            get_theme("hot-pink")
        # The message should help the user pick a real one.
        assert "minimal" in str(exc.value)

    def test_unknown_severity_falls_back_to_muted(self) -> None:
        theme = get_theme("minimal")
        assert theme.severity_style("not-a-severity") == theme.style("vortex.muted")

    def test_themes_differ_in_palette(self) -> None:
        """Themes must actually recolour the font, not just rename themselves."""
        criticals = {t.name: t.severity_style("critical") for t in all_themes()}
        assert len(set(criticals.values())) >= 4, criticals

    def test_minimal_default_stays_restrained(self) -> None:
        """
        The default theme must keep chrome monochrome: structure comes from
        bold/dim weights, and hue is reserved for severity and status.
        """
        theme = get_theme("minimal")
        for token in ("vortex.title", "vortex.accent", "vortex.border", "vortex.header"):
            assert theme.style(token) in ("bold", "dim", "default", ""), token
        assert not theme.banner, "the default theme must not print a wordmark"

    def test_mono_theme_is_ascii_only(self) -> None:
        theme = get_theme("mono")
        assert theme.glyphs == ASCII_GLYPHS
        for glyph in vars(theme.glyphs).values():
            assert glyph.isascii(), glyph

    def test_theme_objects_are_immutable(self) -> None:
        with pytest.raises(Exception):
            get_theme("minimal").name = "tampered"  # type: ignore[misc]


# ─────────────────────────────────────────────────────────────────────────────
# Console factory
# ─────────────────────────────────────────────────────────────────────────────


class TestBuildConsole:
    def test_tokens_render_as_markup(self) -> None:
        console, buf = _capture(get_theme("neon"))
        console.print("[vortex.accent]accented[/vortex.accent]")
        out = buf.getvalue()
        assert "accented" in out
        assert "\x1b[" in out, "expected ANSI colour for a themed token"

    def test_no_color_strips_ansi_but_keeps_text(self) -> None:
        buf = io.StringIO()
        console = build_console(
            get_theme("neon"), no_color=True, file=buf, force_terminal=True, width=80
        )
        console.print("[vortex.accent]accented[/vortex.accent]")
        out = buf.getvalue()
        assert "accented" in out
        assert "38;2;" not in out and "[35m" not in out

    def test_unknown_token_does_not_crash(self) -> None:
        console, buf = _capture()
        console.print("plain text")
        assert "plain text" in buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# UI primitives
# ─────────────────────────────────────────────────────────────────────────────


class TestUIPrimitives:
    def test_banner_is_suppressed_for_minimal_themes(self) -> None:
        theme = get_theme("minimal")
        console, buf = _capture(theme)
        ui.banner(console, theme, "1.0.0")
        assert buf.getvalue() == ""

    def test_banner_prints_for_opted_in_themes(self) -> None:
        theme = get_theme("vortex")
        console, buf = _capture(theme)
        ui.banner(console, theme, "1.2.3")
        out = buf.getvalue()
        assert "█" in out
        assert "v1.2.3" in out

    def test_banner_without_version_omits_it(self) -> None:
        theme = get_theme("vortex")
        console, buf = _capture(theme)
        ui.banner(console, theme)
        assert "v" not in buf.getvalue().split("Testing")[-1]

    def test_scan_header_lists_target_and_settings(self) -> None:
        theme = get_theme("minimal")
        console, buf = _capture(theme)
        ui.scan_header(
            console, theme, "http://target.local", {"Modules": "xss_check", "Depth": 3}
        )
        out = buf.getvalue()
        assert "http://target.local" in out
        assert "Modules" in out and "xss_check" in out
        assert "Depth" in out and "3" in out

    def test_scan_header_aligns_labels(self) -> None:
        """Target must line up with the widest setting label."""
        theme = get_theme("minimal")
        console, buf = _capture(theme, width=60)
        ui.scan_header(console, theme, "http://t.local", {"Endpoint cap": "none"})
        lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
        target_line = next(ln for ln in lines if "http://t.local" in ln)
        cap_line = next(ln for ln in lines if "none" in ln)
        assert target_line.index("http://t.local") == cap_line.index("none")

    def test_phase_renders_index_and_detail(self) -> None:
        theme = get_theme("minimal")
        console, buf = _capture(theme)
        ui.phase(console, theme, 2, "Fuzzing", "9 probe(s)")
        out = buf.getvalue()
        assert "Phase 2" in out and "Fuzzing" in out and "9 probe(s)" in out

    @pytest.mark.parametrize("kind", ["ok", "warn", "error", "info", "group"])
    def test_status_kinds_render(self, kind: str) -> None:
        theme = get_theme("minimal")
        console, buf = _capture(theme)
        ui.status(console, theme, kind, "message", "detail")
        out = buf.getvalue()
        assert "message" in out and "detail" in out

    def test_unknown_status_kind_falls_back_to_info(self) -> None:
        theme = get_theme("minimal")
        console, buf = _capture(theme)
        ui.status(console, theme, "not-a-kind", "still printed")
        assert "still printed" in buf.getvalue()

    def test_status_uses_theme_glyphs(self) -> None:
        theme = get_theme("mono")
        console, buf = _capture(theme)
        ui.status(console, theme, "ok", "done")
        assert "+" in buf.getvalue()


class TestSeverityBar:
    def test_bar_is_exactly_the_requested_width(self) -> None:
        theme = get_theme("minimal")
        counts = {"critical": 1, "high": 2, "medium": 5, "low": 9, "informational": 30}
        assert len(ui.severity_bar(theme, counts, width=40).plain) == 40

    def test_rare_severity_still_gets_a_cell(self) -> None:
        theme = get_theme("minimal")
        bar = ui.severity_bar(theme, {"critical": 1, "informational": 999}, width=20)
        assert len(bar.plain) == 20
        # The lone CRITICAL must survive rounding and be styled as critical.
        spans = [s for s in bar.spans if s.style == theme.severity_style("critical")]
        assert spans and spans[0].end - spans[0].start >= 1

    def test_empty_counts_render_nothing(self) -> None:
        theme = get_theme("minimal")
        assert ui.severity_bar(theme, {}, width=20).plain == ""
        assert ui.severity_bar(theme, {"high": 0}, width=20).plain == ""

    def test_zero_width_renders_nothing(self) -> None:
        theme = get_theme("minimal")
        assert ui.severity_bar(theme, {"high": 3}, width=0).plain == ""

    def test_counts_line_lists_only_present_severities(self) -> None:
        theme = get_theme("minimal")
        line = ui.severity_counts_line(theme, {"critical": 2, "high": 0, "low": 7}).plain
        assert "2 critical" in line and "7 low" in line
        assert "high" not in line

    def test_bar_uses_theme_bar_glyph(self) -> None:
        bar = ui.severity_bar(get_theme("mono"), {"high": 4}, width=8).plain
        assert bar == "#" * 8


class TestThemeTable:
    def test_lists_every_theme_and_marks_the_active_one(self) -> None:
        active = get_theme("neon")
        console, buf = _capture(active, width=130)
        ui.theme_table(console, active)
        out = buf.getvalue()
        for name in THEME_NAMES:
            assert name in out
        assert "(active)" in out

    def test_active_marker_is_optional(self) -> None:
        console, buf = _capture(width=130)
        ui.theme_table(console)
        assert "(active)" not in buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# Config / env plumbing
# ─────────────────────────────────────────────────────────────────────────────


class TestThemeConfig:
    def test_env_override_sets_ui_theme(self) -> None:
        config: Dict = {}
        apply_env_overrides(config, {"VORTEX_THEME": "dracula"})
        assert config["ui"]["theme"] == "dracula"

    @pytest.mark.parametrize(
        "raw,expected",
        [("1", True), ("true", True), ("YES", True), ("on", True),
         ("0", False), ("false", False), ("no", False), ("off", False)],
    )
    def test_env_no_color_parses_booleans(self, raw: str, expected: bool) -> None:
        config: Dict = {}
        apply_env_overrides(config, {"VORTEX_NO_COLOR": raw})
        assert config["ui"]["no_color"] is expected

    def test_env_no_color_rejects_garbage(self) -> None:
        with pytest.raises(ConfigError):
            apply_env_overrides({}, {"VORTEX_NO_COLOR": "maybe"})

    def test_validate_accepts_known_theme(self) -> None:
        validate_config({"ui": {"theme": "gruvbox", "no_color": True}})

    def test_validate_rejects_unknown_theme(self) -> None:
        with pytest.raises(ConfigError) as exc:
            validate_config({"ui": {"theme": "chartreuse"}})
        assert "ui.theme" in str(exc.value)

    def test_validate_rejects_non_string_theme(self) -> None:
        with pytest.raises(ConfigError):
            validate_config({"ui": {"theme": 7}})

    def test_validate_rejects_non_bool_no_color(self) -> None:
        with pytest.raises(ConfigError):
            validate_config({"ui": {"no_color": "yes"}})

    def test_validate_rejects_non_mapping_ui_section(self) -> None:
        with pytest.raises(ConfigError):
            validate_config({"ui": ["minimal"]})

    def test_shipped_config_yaml_validates(self) -> None:
        import yaml

        path = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
        with open(path, "r", encoding="utf-8") as fh:
            validate_config(yaml.safe_load(fh))


# ─────────────────────────────────────────────────────────────────────────────
# CLI wiring
# ─────────────────────────────────────────────────────────────────────────────


class TestCLIThemeFlags:
    def test_parser_exposes_theme_flags(self) -> None:
        args = scanner._build_parser().parse_args(
            ["-u", "http://t.local", "--theme", "neon", "--no-color"]
        )
        assert args.theme == "neon"
        assert args.no_color is True

    def test_theme_defaults_to_none_so_config_can_win(self) -> None:
        args = scanner._build_parser().parse_args(["-u", "http://t.local"])
        assert args.theme is None
        assert args.no_color is False
        assert args.list_themes is False

    def test_unknown_theme_is_rejected_by_argparse(self) -> None:
        with pytest.raises(SystemExit):
            scanner._build_parser().parse_args(["-u", "http://t.local", "--theme", "nope"])

    def test_resolve_prefers_cli_flag_over_config(self) -> None:
        args = scanner._build_parser().parse_args(["-u", "http://t.local", "--theme", "nord"])
        theme, no_color = scanner._resolve_theme(args, {"ui": {"theme": "matrix"}})
        assert theme.name == "nord"
        assert no_color is False

    def test_resolve_falls_back_to_config(self) -> None:
        args = scanner._build_parser().parse_args(["-u", "http://t.local"])
        theme, _ = scanner._resolve_theme(args, {"ui": {"theme": "matrix"}})
        assert theme.name == "matrix"

    def test_resolve_falls_back_to_default(self) -> None:
        args = scanner._build_parser().parse_args(["-u", "http://t.local"])
        theme, no_color = scanner._resolve_theme(args, {})
        assert theme.name == DEFAULT_THEME_NAME
        assert no_color is False

    def test_resolve_reads_env_when_no_config_is_loaded(self, monkeypatch) -> None:
        monkeypatch.setenv("VORTEX_THEME", "solarized")
        monkeypatch.setenv("VORTEX_NO_COLOR", "1")
        args = scanner._build_parser().parse_args(["-u", "http://t.local"])
        theme, no_color = scanner._resolve_theme(args)
        assert theme.name == "solarized"
        assert no_color is True

    def test_cli_flag_beats_env(self, monkeypatch) -> None:
        monkeypatch.setenv("VORTEX_THEME", "solarized")
        args = scanner._build_parser().parse_args(["-u", "http://t.local", "--theme", "neon"])
        assert scanner._resolve_theme(args)[0].name == "neon"

    def test_config_no_color_is_honoured(self) -> None:
        args = scanner._build_parser().parse_args(["-u", "http://t.local"])
        _, no_color = scanner._resolve_theme(args, {"ui": {"no_color": True}})
        assert no_color is True

    def test_resolve_raises_on_bad_config_theme(self) -> None:
        args = scanner._build_parser().parse_args(["-u", "http://t.local"])
        with pytest.raises(ThemeError):
            scanner._resolve_theme(args, {"ui": {"theme": "chartreuse"}})

    def test_list_themes_exits_zero_and_prints(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr(sys, "argv", ["vortex", "--list-themes"])
        assert scanner.main() == 0
        out = capsys.readouterr().out
        for name in THEME_NAMES:
            assert name in out

    def test_list_modules_still_works_with_a_theme(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr(sys, "argv", ["vortex", "--list-modules", "--theme", "matrix"])
        assert scanner.main() == 0
        assert "Registered Scanner Modules" in capsys.readouterr().out

    def test_target_still_required_for_a_scan(self, monkeypatch) -> None:
        monkeypatch.setattr(sys, "argv", ["vortex"])
        with pytest.raises(SystemExit):
            scanner.main()


class TestThemedHelpers:
    def test_module_table_renders_with_any_theme(self) -> None:
        for name in ("minimal", "mono", "neon"):
            theme = get_theme(name)
            console, buf = _capture(theme, width=130)
            scanner._print_module_table(console, theme)
            out = buf.getvalue()
            assert "xss_check" in out
            assert "module(s) registered" in out

    def test_module_table_defaults_are_usable(self) -> None:
        # No console and no theme: must not raise.
        scanner._print_module_table()

    def test_fuzz_progress_uses_the_theme_spinner(self) -> None:
        theme = get_theme("neon")
        console, _ = _capture(theme)
        progress = scanner._make_fuzz_progress(console, theme)
        spinners = [
            col for col in progress.columns if hasattr(col, "spinner")
        ]
        assert spinners and spinners[0].spinner.frames

    def test_fuzz_progress_without_theme_still_builds(self) -> None:
        console, _ = _capture()
        assert scanner._make_fuzz_progress(console).columns


# ─────────────────────────────────────────────────────────────────────────────
# Themed reporter dashboard
# ─────────────────────────────────────────────────────────────────────────────


class TestThemedReporter:
    @pytest.mark.parametrize("name", THEME_NAMES)
    def test_dashboard_renders_under_every_theme(self, name: str) -> None:
        theme = get_theme(name)
        console, buf = _capture(theme, width=120)
        Reporter(
            [_finding(), _finding("Missing CSP", Severity.MEDIUM, "headers_audit")],
            "http://target.local",
            {"scan_duration_s": "1.00"},
            console=console,
            theme=theme,
            deduplicate=False,
        ).print_terminal_summary()
        out = buf.getvalue()
        assert "Reflected XSS" in out
        assert "CRITICAL" in out and "MEDIUM" in out
        assert "Scan Metadata" in out

    def test_reporter_defaults_to_the_default_theme(self) -> None:
        reporter = Reporter([_finding()], "http://target.local")
        assert reporter._theme is DEFAULT_THEME

    def test_severity_colour_follows_the_theme(self) -> None:
        """The same finding must be painted differently by different themes."""
        rendered = {}
        for name in ("minimal", "neon"):
            theme = get_theme(name)
            console, buf = _capture(theme, width=120)
            Reporter(
                [_finding()], "http://target.local", console=console, theme=theme
            ).print_terminal_summary()
            rendered[name] = buf.getvalue()
        assert rendered["minimal"] != rendered["neon"]

    def test_empty_scan_reports_no_findings(self) -> None:
        theme = get_theme("minimal")
        console, buf = _capture(theme)
        Reporter([], "http://target.local", console=console, theme=theme).print_terminal_summary()
        out = buf.getvalue()
        assert "No findings reported" in out

    def test_missing_parameter_uses_the_theme_dash(self) -> None:
        theme = get_theme("mono")
        console, buf = _capture(theme, width=120)
        Reporter(
            [_finding(parameter=None)], "http://t.local", console=console, theme=theme
        ).print_terminal_summary()
        # mono's dash is ASCII, so the unicode em dash must not appear in the row.
        assert "—" not in buf.getvalue()

    def test_share_bar_marks_every_non_empty_bucket(self) -> None:
        theme = get_theme("minimal")
        console, buf = _capture(theme, width=120)
        findings = [_finding()] + [
            _finding(f"Info {i}", Severity.INFORMATIONAL, "headers_audit") for i in range(50)
        ]
        Reporter(
            findings, "http://t.local", console=console, theme=theme, deduplicate=False
        ).print_terminal_summary()
        out = buf.getvalue()
        # 1 of 51 findings still earns at least one filled cell.
        critical_row = next(ln for ln in out.splitlines() if "CRITICAL" in ln)
        assert theme.glyphs.bar_full in critical_row

    def test_save_notice_is_themed(self, tmp_path) -> None:
        theme = get_theme("minimal")
        console, buf = _capture(theme)
        path = tmp_path / "scan.json"
        Reporter(
            [_finding()], "http://t.local", console=console, theme=theme
        ).save_json(str(path))
        out = buf.getvalue()
        assert "JSON report saved" in out
        assert str(path) in out.replace("\n", "")
