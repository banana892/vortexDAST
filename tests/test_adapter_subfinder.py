"""
VortexDAST – tests/test_adapter_subfinder.py
────────────────────────────────────────────────────────────────────────────
Tests for ``adapters/subfinder_adapter.py``.

subfinder writes JSON-Lines to stdout like nuclei/httpx, so this is a plain
fake-binary-on-PATH test, hermetic: no real subfinder, no network queries to
any public source.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from adapters.subfinder_adapter import SubfinderAdapter
from core.orchestrator import ScanContext, discover_adapters
from modules.base import Confidence, Severity

# Modeled on real `subfinder -json` output: two distinct hosts from different
# sources, plus a duplicate (subfinder's own sources often overlap) that must
# be collapsed to one finding.
_SUBFINDER_JSONL = "\n".join(
    [
        '{"host": "api.app.local", "input": "app.local", "source": "crtsh"}',
        '{"host": "dev.app.local", "input": "app.local", "source": "virustotal"}',
        '{"host": "api.app.local", "input": "app.local", "source": "virustotal"}',
    ]
)

_FAKE_SUBFINDER = r'''#!/usr/bin/env python3
import sys
print('{"host": "api.app.local", "input": "app.local", "source": "crtsh"}')
print('{"host": "dev.app.local", "input": "app.local", "source": "virustotal"}')
'''


def _write_fake(dir_path: Path) -> Path:
    script = dir_path / "subfinder"
    script.write_text(_FAKE_SUBFINDER)
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


@pytest.fixture
def fake_subfinder_on_path(tmp_path, monkeypatch):
    _write_fake(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    return tmp_path


# ─────────────────────────────────────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────────────────────────────────────


def test_subfinder_adapter_is_discovered():
    registry = discover_adapters()
    assert registry["subfinder"] is SubfinderAdapter


# ─────────────────────────────────────────────────────────────────────────────
# build_command
# ─────────────────────────────────────────────────────────────────────────────


class TestSubfinderCommand:
    def test_argv_shape(self):
        argv = SubfinderAdapter().build_command("https://app.local:8443/path", ScanContext())
        assert argv[0] == "subfinder"
        assert argv[argv.index("-d") + 1] == "app.local"
        assert "-json" in argv
        assert "-silent" in argv

    def test_bare_host_target(self):
        argv = SubfinderAdapter().build_command("app.local", ScanContext())
        assert argv[argv.index("-d") + 1] == "app.local"

    def test_target_is_a_single_argv_element(self):
        evil = "app.local;rm -rf ~"
        argv = SubfinderAdapter().build_command(evil, ScanContext())
        # urlsplit().hostname on a schemeless string with no "/" returns None,
        # so the raw (stripped) string is used as-is — still one argv element.
        assert argv.count(evil) == 1


# ─────────────────────────────────────────────────────────────────────────────
# parse
# ─────────────────────────────────────────────────────────────────────────────


class TestSubfinderParse:
    def test_one_finding_per_distinct_host(self):
        findings = SubfinderAdapter().parse(_SUBFINDER_JSONL)
        hosts = {f.extra["discovered_host"] for f in findings}
        assert hosts == {"api.app.local", "dev.app.local"}
        assert len(findings) == 2  # the duplicate api.app.local was collapsed

    def test_informational_and_certain(self):
        findings = SubfinderAdapter().parse(_SUBFINDER_JSONL)
        assert all(f.severity == Severity.INFORMATIONAL for f in findings)
        assert all(f.confidence == Confidence.CERTAIN for f in findings)

    def test_source_surfaced_in_evidence_and_extra(self):
        findings = SubfinderAdapter().parse(_SUBFINDER_JSONL)
        api = next(f for f in findings if f.extra["discovered_host"] == "api.app.local")
        assert api.extra["source"] == "crtsh"  # first-seen record wins
        assert "source=crtsh" in api.evidence

    def test_url_is_the_bare_host(self):
        findings = SubfinderAdapter().parse(_SUBFINDER_JSONL)
        api = next(f for f in findings if f.extra["discovered_host"] == "api.app.local")
        assert api.url == "api.app.local"

    def test_empty_or_malformed(self):
        assert SubfinderAdapter().parse("") == []
        assert SubfinderAdapter().parse("not json") == []
        assert SubfinderAdapter().parse('{"no_host": true}') == []


# ─────────────────────────────────────────────────────────────────────────────
# run (end to end, over the fake binary)
# ─────────────────────────────────────────────────────────────────────────────


class TestSubfinderRun:
    def test_end_to_end_with_fake_binary(self, fake_subfinder_on_path):
        adapter = SubfinderAdapter()
        assert adapter.is_available() is True
        findings = adapter.run("https://app.local/", ScanContext(tool_timeout=30))
        assert len(findings) == 2

    def test_absent_binary_skips_cleanly(self, monkeypatch):
        monkeypatch.setattr(SubfinderAdapter, "is_available", lambda self: False)
        assert SubfinderAdapter().run("https://app.local/", ScanContext()) == []
