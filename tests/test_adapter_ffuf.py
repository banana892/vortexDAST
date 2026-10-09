"""
VortexDAST – tests/test_adapter_ffuf.py
────────────────────────────────────────────────────────────────────────────
Tests for ``adapters/ffuf_adapter.py`` and the ANSI-tolerant JSONL parser.

The fixture is real ``ffuf -json -s`` output captured from a local server —
including the ``ESC[2K`` erase-line prefix ffuf puts on every record and the
base64 ``input.FUZZ`` that, under ``-ac``, belongs to a calibration request.
Runs are hermetic: a fake ``ffuf`` script on PATH replays that output.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from adapters.ffuf_adapter import FfufAdapter
from core.orchestrator import ScanContext, discover_adapters, parse_jsonl
from modules.base import Confidence, Severity
from scanner import _build_parser, run_scan

_E = "\x1b[2K"
_FFUF_OUTPUT = (
    _E + '{"input":{"FFUFHASH":"N2RlNjYx","FUZZ":"Lmh0YWNjZXNzWWtUTUtRTEc="},"position":1,'
    '"status":301,"length":0,"words":1,"lines":1,"content-type":"","redirectlocation":"/admin/",'
    '"url":"http://app.local/admin","host":"app.local"}\n'
    + _E + '{"input":{"FUZZ":"LmVudg=="},"position":2,"status":200,"length":9,"words":1,"lines":2,'
    '"content-type":"application/octet-stream","redirectlocation":"","url":"http://app.local/.env",'
    '"host":"app.local"}\n'
    + _E + '{"input":{"FUZZ":"LmdpdC9jb25maWc="},"position":3,"status":403,"length":12,'
    '"url":"http://app.local/.git/config","host":"app.local"}\n'
    + _E + '{"input":{"FUZZ":"eA=="},"position":4,"status":200,"length":5,'
    '"url":"http://app.local/custom-thing","host":"app.local"}\n'
    # Duplicate hit (same URL) must be reported once.
    + _E + '{"input":{"FUZZ":"LmVudg=="},"position":5,"status":200,"length":9,'
    '"url":"http://app.local/.env","host":"app.local"}\n'
)


def _fake_ffuf(bindir: Path, stdout: str) -> None:
    script = bindir / "ffuf"
    script.write_text(
        "#!/usr/bin/env bash\ncat <<'VORTEX_EOF'\n" + stdout + "VORTEX_EOF\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture
def bindir(tmp_path, monkeypatch) -> Path:
    d = tmp_path / "bin"
    d.mkdir()
    monkeypatch.setenv("PATH", str(d) + os.pathsep + os.environ["PATH"])
    return d


def _by_path(findings):
    return {f.payload: f for f in findings}


# ─────────────────────────────────────────────────────────────────────────────
# Shared parser
# ─────────────────────────────────────────────────────────────────────────────


def test_parse_jsonl_strips_ansi_control_sequences():
    raw = '\x1b[2K{"a":1}\n\x1b[1;31m{"b":2}\x1b[0m\n'
    assert list(parse_jsonl(raw)) == [{"a": 1}, {"b": 2}]


def test_ffuf_is_discovered():
    assert discover_adapters()["ffuf"] is FfufAdapter


# ─────────────────────────────────────────────────────────────────────────────
# Parsing / severity
# ─────────────────────────────────────────────────────────────────────────────


class TestParse:
    def test_real_output_parses_and_dedupes(self):
        findings = FfufAdapter().parse(_FFUF_OUTPUT)
        assert sorted(_by_path(findings)) == ["/.env", "/.git/config", "/admin", "/custom-thing"]
        assert len(findings) == 4

    def test_url_not_base64_input_is_the_source_of_truth(self):
        # Record 1's FUZZ decodes to a calibration string, but the hit is /admin.
        admin = _by_path(FfufAdapter().parse(_FFUF_OUTPUT))["/admin"]
        assert admin.url == "http://app.local/admin"

    def test_catalogue_hit_keeps_catalogue_severity(self):
        env = _by_path(FfufAdapter().parse(_FFUF_OUTPUT))["/.env"]
        assert env.severity == Severity.HIGH
        assert env.confidence == Confidence.FIRM
        assert env.title == "Exposed Configuration File: /.env"
        assert env.extra["tool"] == "ffuf"
        assert env.extra["category"] == "config"

    def test_forbidden_hit_is_downgraded(self):
        git = _by_path(FfufAdapter().parse(_FFUF_OUTPUT))["/.git/config"]
        assert git.severity == Severity.MEDIUM  # catalogue HIGH, minus one for 403
        assert git.confidence == Confidence.TENTATIVE

    def test_redirect_is_informational(self):
        admin = _by_path(FfufAdapter().parse(_FFUF_OUTPUT))["/admin"]
        assert admin.severity == Severity.INFORMATIONAL
        assert "redirects to /admin/" in admin.evidence

    def test_non_catalogue_hit_is_conservative(self):
        other = _by_path(FfufAdapter().parse(_FFUF_OUTPUT))["/custom-thing"]
        assert other.severity == Severity.LOW
        assert other.title == "Discovered Path: /custom-thing"

    def test_records_without_url_or_status_are_skipped(self):
        raw = '{"status":200}\n{"url":"http://a/x"}\nnot json\n'
        assert FfufAdapter().parse(raw) == []


# ─────────────────────────────────────────────────────────────────────────────
# Command building
# ─────────────────────────────────────────────────────────────────────────────


class TestCommand:
    def _argv(self, target="https://app.local/deep/page?q=1", **extra):
        adapter = FfufAdapter()
        ctx = ScanContext(tool_timeout=120)
        ctx.extra.update(extra)
        try:
            return adapter.build_command(target, ctx), adapter
        finally:
            if adapter._temp_wordlist:
                os.unlink(adapter._temp_wordlist)

    def test_fuzzes_origin_with_json_and_calibration(self):
        argv, _ = self._argv()
        assert argv[0] == "ffuf"
        assert argv[argv.index("-u") + 1] == "https://app.local/FUZZ"
        for flag in ("-json", "-s", "-noninteractive", "-ac"):
            assert flag in argv

    def test_maxtime_sits_inside_the_hard_timeout(self):
        argv, _ = self._argv()
        assert int(argv[argv.index("-maxtime") + 1]) < 120

    def test_honours_scan_throughput_and_auth(self):
        argv, _ = self._argv(
            threads=7, rate_limit_rps=2.5, request_timeout=9,
            headers={"Authorization": "Bearer t"}, cookie="sid=abc",
        )
        assert argv[argv.index("-t") + 1] == "7"
        assert argv[argv.index("-rate") + 1] == "2"
        assert argv[argv.index("-timeout") + 1] == "9"
        assert argv[argv.index("-H") + 1] == "Authorization: Bearer t"
        assert argv[argv.index("-b") + 1] == "sid=abc"

    def test_sub_one_rate_never_becomes_unlimited(self):
        argv, _ = self._argv(rate_limit_rps=0.5)
        assert argv[argv.index("-rate") + 1] == "1"

    def test_zero_rate_means_no_rate_flag(self):
        argv, _ = self._argv(rate_limit_rps=0)
        assert "-rate" not in argv

    def test_default_wordlist_is_the_catalogue(self):
        adapter = FfufAdapter()
        argv = adapter.build_command("https://app.local", ScanContext())
        path = argv[argv.index("-w") + 1]
        try:
            words = Path(path).read_text().split()
            assert ".env" in words and ".git/config" in words
            assert not any(w.startswith("/") for w in words)
        finally:
            os.unlink(path)

    def test_custom_wordlist_is_used_verbatim(self, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("a\nb\n")
        argv, adapter = self._argv(ffuf_wordlist=str(wl))
        assert argv[argv.index("-w") + 1] == str(wl)
        assert adapter._temp_wordlist is None


# ─────────────────────────────────────────────────────────────────────────────
# Runs
# ─────────────────────────────────────────────────────────────────────────────


class TestRun:
    def test_end_to_end_with_fake_binary_and_cleanup(self, bindir, monkeypatch):
        _fake_ffuf(bindir, _FFUF_OUTPUT)
        created = []
        real_wordlist = FfufAdapter._wordlist

        def spy(self, ctx):
            path = real_wordlist(self, ctx)
            created.append(path)
            return path

        monkeypatch.setattr(FfufAdapter, "_wordlist", spy)
        findings = FfufAdapter().run("http://app.local/", ScanContext())
        assert len(findings) == 4
        assert len(created) == 1
        assert not os.path.exists(created[0])  # temp catalogue wordlist removed

    def test_absent_binary_skips_cleanly(self, monkeypatch):
        monkeypatch.setattr(FfufAdapter, "is_available", lambda self: False)
        assert FfufAdapter().run("http://app.local/", ScanContext()) == []


def test_missing_ffuf_wordlist_aborts_scan(tmp_path):
    args = _build_parser().parse_args([
        "-u", "http://127.0.0.1:9/", "--tools", "ffuf",
        "--ffuf-wordlist", str(tmp_path / "nope.txt"),
    ])
    assert run_scan(args) == 1
