"""
VortexDAST – tests/test_orchestration_cli.py
────────────────────────────────────────────────────────────────────────────
CLI wiring for the orchestration layer: ``--tools`` / ``--no-tools`` /
``--tool-timeout`` / ``--list-tools``, and the external-tool phase inside
``scanner.run_scan``.

The end-to-end tests drive the real ``run_scan`` against an in-process HTTP
server on 127.0.0.1, with a *fake* ``nuclei`` binary first on ``PATH`` — so the
whole crawl → modules → tools → report path runs with no network access and no
real external tool.
"""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterator, Tuple

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scanner
from core.theme import build_console, get_theme
from scanner import _build_parser, _resolve_tools, run_scan


# ─────────────────────────────────────────────────────────────────────────────
# Helpers / fixtures
# ─────────────────────────────────────────────────────────────────────────────

_NUCLEI_CRITICAL = (
    '{"template-id":"CVE-2099-0001","info":{"name":"Fake Critical",'
    '"severity":"critical"},"matched-at":"__TARGET__"}\n'
)


def _write_script(dir_path: Path, name: str, body: str) -> Path:
    script = dir_path / name
    script.write_text("#!/usr/bin/env bash\n" + body)
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


def _fake_nuclei(dir_path: Path, stdout: str, *, prelude: str = "", exit_code: int = 0) -> None:
    _write_script(
        dir_path,
        "nuclei",
        prelude
        + "cat <<'VORTEX_EOF'\n"
        + stdout
        + "VORTEX_EOF\n"
        + f"exit {exit_code}\n",
    )


@pytest.fixture
def target_site() -> Iterator[str]:
    class Site(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b"<html><body>hello</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()


@pytest.fixture
def tool_dir(tmp_path, monkeypatch) -> Path:
    """A directory placed first on PATH for fake tool binaries."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    return bindir


def _scan(target: str, out: Path, *extra: str) -> Tuple[int, Dict[str, Any]]:
    """Run a minimal, fast, local-only scan and return (exit_code, report)."""
    args = _build_parser().parse_args([
        "-u", target, "-m", "headers_audit", "--max-depth", "0",
        "--rate-limit", "0", "--disable-anomaly-detection",
        "-o", str(out), *extra,
    ])
    code = run_scan(args)
    return code, json.loads(out.read_text())


def _tool_findings(report: Dict[str, Any], tool: str):
    return [f for f in report["findings"] if (f.get("extra") or {}).get("tool") == tool]


# ─────────────────────────────────────────────────────────────────────────────
# Parser defaults
# ─────────────────────────────────────────────────────────────────────────────


class TestParser:
    def test_defaults_run_no_tools(self):
        args = _build_parser().parse_args(["-u", "http://x"])
        assert args.tools is None
        assert args.no_tools is False
        assert args.tool_timeout == 600.0
        assert args.list_tools is False

    def test_flags_parse(self):
        args = _build_parser().parse_args([
            "-u", "http://x", "--tools", "nuclei,nmap", "--no-tools",
            "--tool-timeout", "30",
        ])
        assert args.tools == "nuclei,nmap"
        assert args.no_tools is True
        assert args.tool_timeout == 30.0


# ─────────────────────────────────────────────────────────────────────────────
# _resolve_tools
# ─────────────────────────────────────────────────────────────────────────────


class TestResolveTools:
    @pytest.mark.parametrize("raw", [None, "", "   "])
    def test_empty_selects_nothing(self, raw):
        assert _resolve_tools(raw) == []

    def test_explicit_list_keeps_order(self):
        assert _resolve_tools("nuclei,nmap") == ["nuclei", "nmap"]

    def test_whitespace_and_duplicates(self):
        assert _resolve_tools(" nmap , nmap ,nuclei ") == ["nmap", "nuclei"]

    def test_all_includes_every_real_adapter(self):
        # Subset, not equality: test-defined stub adapters may also be live.
        assert {"nuclei", "nmap", "httpx"} <= set(_resolve_tools("all"))
        assert {"nuclei", "nmap", "httpx"} <= set(_resolve_tools("ALL"))

    def test_unknown_tool_exits(self, capsys):
        with pytest.raises(SystemExit):
            _resolve_tools("nuclei,definitely-not-a-tool")
        assert "definitely-not-a-tool" in capsys.readouterr().err


# ─────────────────────────────────────────────────────────────────────────────
# --list-tools
# ─────────────────────────────────────────────────────────────────────────────


class TestListTools:
    def test_list_tools_exits_zero_without_target(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["vortex", "--list-tools"])
        assert scanner.main() == 0
        out = capsys.readouterr().out
        assert "External-Tool Adapters" in out
        for name in ("nuclei", "nmap", "httpx"):
            assert name in out

    def test_table_reports_install_state(self, tool_dir):
        _fake_nuclei(tool_dir, "")
        buf = io.StringIO()
        theme = get_theme("mono")  # ASCII glyphs → easy to assert
        console = build_console(
            theme, no_color=True, file=buf, force_terminal=True, width=160,
        )
        scanner._print_tool_table(console, theme)
        out = buf.getvalue()
        nuclei_row = next(line for line in out.splitlines() if " nuclei " in line)
        assert theme.glyphs.ok in nuclei_row
        assert "installed" in out

    def test_table_defaults_are_usable(self):
        scanner._print_tool_table()  # no console, no theme: must not raise


# ─────────────────────────────────────────────────────────────────────────────
# run_scan end-to-end
# ─────────────────────────────────────────────────────────────────────────────


class TestRunScanOrchestration:
    def test_tool_findings_are_folded_into_the_report(self, target_site, tool_dir, tmp_path):
        _fake_nuclei(tool_dir, _NUCLEI_CRITICAL.replace("__TARGET__", target_site))
        code, report = _scan(target_site, tmp_path / "r.json", "--tools", "nuclei")

        nuclei = _tool_findings(report, "nuclei")
        assert len(nuclei) == 1
        assert nuclei[0]["title"] == "Fake Critical"
        assert nuclei[0]["severity"] == "critical"
        assert report["scan_metadata"]["tools_run"] == "nuclei"
        # A CRITICAL from an external tool gates CI exactly like a native one.
        assert code == 2

    def test_no_tools_overrides_tools(self, target_site, tool_dir, tmp_path):
        _fake_nuclei(tool_dir, _NUCLEI_CRITICAL.replace("__TARGET__", target_site))
        code, report = _scan(
            target_site, tmp_path / "r.json", "--tools", "nuclei", "--no-tools",
        )
        assert _tool_findings(report, "nuclei") == []
        assert report["scan_metadata"]["tools_run"] == "none"
        assert code == 0

    def test_default_scan_runs_no_tools(self, target_site, tool_dir, tmp_path):
        _fake_nuclei(tool_dir, _NUCLEI_CRITICAL.replace("__TARGET__", target_site))
        _code, report = _scan(target_site, tmp_path / "r.json")
        assert _tool_findings(report, "nuclei") == []
        assert report["scan_metadata"]["tools_run"] == "none"

    def test_failing_tool_does_not_sink_the_scan(self, target_site, tool_dir, tmp_path):
        _fake_nuclei(tool_dir, "garbage, not json\n", exit_code=1)
        code, report = _scan(target_site, tmp_path / "r.json", "--tools", "nuclei")
        # Scan completes; native findings (missing headers) still reported.
        assert _tool_findings(report, "nuclei") == []
        assert report["summary"]["total_findings"] >= 1
        assert code == 0

    def test_tool_timeout_flag_is_enforced(self, target_site, tool_dir, tmp_path):
        # The finding is only printed *after* sleeping; if --tool-timeout is
        # honoured the tool is killed first and contributes nothing.
        _fake_nuclei(
            tool_dir,
            _NUCLEI_CRITICAL.replace("__TARGET__", target_site),
            prelude="sleep 5\n",
        )
        code, report = _scan(
            target_site, tmp_path / "r.json", "--tools", "nuclei", "--tool-timeout", "0.5",
        )
        assert _tool_findings(report, "nuclei") == []
        assert code == 0

    def test_missing_tool_is_skipped_not_fatal(self, target_site, tool_dir, tmp_path, monkeypatch):
        # httpx is not on PATH in tool_dir; make sure a real one can't be found.
        monkeypatch.setattr("adapters.httpx_adapter.HttpxAdapter.is_available", lambda self: False)
        code, report = _scan(target_site, tmp_path / "r.json", "--tools", "httpx")
        assert _tool_findings(report, "httpx") == []
        assert report["scan_metadata"]["tools_run"] == "httpx"
        assert code == 0
