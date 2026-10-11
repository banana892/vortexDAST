"""
VortexDAST – tests/test_adapter_nikto.py
────────────────────────────────────────────────────────────────────────────
Tests for ``adapters/nikto_adapter.py``.

nikto only writes JSON to a file (never stdout), so the adapter overrides
``run()`` to pass it a temp path and read that back — the end-to-end test
uses a fake ``nikto`` binary that, instead of printing JSON, *writes* it to
whatever path follows ``-output`` in its own argv, exactly like the real
tool. Hermetic: no real nikto, no network, no scanning of anything.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from adapters.nikto_adapter import NiktoAdapter
from core.orchestrator import ScanContext, discover_adapters
from modules.base import Confidence, Severity

# Modeled on real `nikto -Format json` output: a header-hygiene note (no
# references), a CVE-tagged finding, and a vulnerability missing its own
# "msg" (must be skipped rather than producing a blank finding).
_NIKTO_JSON = json.dumps(
    [
        {
            "host": "app.local",
            "ip": "10.0.0.5",
            "port": 443,
            "vulnerabilities": [
                {
                    "id": "013587",
                    "method": "GET",
                    "msg": "Suggested security header missing: x-content-type-options.",
                    "references": "",
                    "url": "/",
                },
                {
                    "id": "007303",
                    "method": "GET",
                    "msg": "JAMon admin interface identified; XSS in versions <= 2.7.",
                    "references": "CVE-2013-6235",
                    "url": "/JAMonAdmin.jsp",
                },
                {"id": "999999", "method": "GET", "msg": "", "references": "", "url": "/blank"},
            ],
        }
    ]
)

_FAKE_NIKTO = r'''#!/usr/bin/env python3
import sys
out = sys.argv[sys.argv.index("-output") + 1]
with open(out, "w") as fh:
    fh.write(__PAYLOAD__)
'''


def _write_fake_nikto(dir_path: Path, payload: str, exit_code: int = 0) -> Path:
    script = dir_path / "nikto"
    source = _FAKE_NIKTO.replace("__PAYLOAD__", repr(payload)) + f"\nsys.exit({exit_code})\n"
    script.write_text(source)
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


@pytest.fixture
def fake_nikto_on_path(tmp_path, monkeypatch):
    """Put a fake ``nikto`` first on PATH (shadowing any real install)."""
    _write_fake_nikto(tmp_path, _NIKTO_JSON)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    return tmp_path


# ─────────────────────────────────────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────────────────────────────────────


def test_nikto_adapter_is_discovered():
    registry = discover_adapters()
    assert registry["nikto"] is NiktoAdapter


# ─────────────────────────────────────────────────────────────────────────────
# build_command
# ─────────────────────────────────────────────────────────────────────────────


class TestNiktoCommand:
    def test_argv_shape(self):
        adapter = NiktoAdapter()
        adapter._output_path = "/tmp/out.json"
        argv = adapter.build_command("http://app.local/", ScanContext(tool_timeout=120))
        assert argv[0] == "nikto"
        assert argv[argv.index("-h") + 1] == "http://app.local/"
        assert argv[argv.index("-Format") + 1] == "json"
        assert argv[argv.index("-output") + 1] == "/tmp/out.json"

    def test_maxtime_derived_from_budget_with_buffer(self):
        adapter = NiktoAdapter()
        argv = adapter.build_command("http://app.local/", ScanContext(tool_timeout=100))
        assert argv[argv.index("-maxtime") + 1] == "85s"

    def test_maxtime_has_a_floor(self):
        adapter = NiktoAdapter()
        argv = adapter.build_command("http://app.local/", ScanContext(tool_timeout=5))
        assert argv[argv.index("-maxtime") + 1] == "10s"

    def test_target_is_a_single_argv_element(self):
        evil = "http://app.local/;rm -rf ~"
        argv = NiktoAdapter().build_command(evil, ScanContext())
        assert argv.count(evil) == 1


# ─────────────────────────────────────────────────────────────────────────────
# parse
# ─────────────────────────────────────────────────────────────────────────────


class TestNiktoParse:
    def test_maps_findings_and_skips_blank_msg(self):
        adapter = NiktoAdapter()
        adapter._target = "http://app.local/"
        findings = adapter.parse(_NIKTO_JSON)
        assert len(findings) == 2  # the blank-msg entry is dropped

    def test_generic_finding_is_informational_tentative(self):
        adapter = NiktoAdapter()
        adapter._target = "http://app.local/"
        findings = adapter.parse(_NIKTO_JSON)
        generic = next(f for f in findings if "x-content-type-options" in f.title)
        assert generic.severity == Severity.INFORMATIONAL
        assert generic.confidence == Confidence.TENTATIVE
        assert generic.cvss_score is None
        assert generic.url == "http://app.local/"

    def test_cve_tagged_finding_is_medium_firm_with_cvss(self):
        adapter = NiktoAdapter()
        adapter._target = "http://app.local/"
        findings = adapter.parse(_NIKTO_JSON)
        cve = next(f for f in findings if "JAMon" in f.title)
        assert cve.severity == Severity.MEDIUM
        assert cve.confidence == Confidence.FIRM
        assert cve.cvss_score is not None
        assert cve.url == "http://app.local/JAMonAdmin.jsp"
        assert cve.extra["references"] == "CVE-2013-6235"

    def test_empty_or_malformed(self):
        assert NiktoAdapter().parse("") == []
        assert NiktoAdapter().parse("not json") == []
        assert NiktoAdapter().parse(json.dumps({"not": "a list"})) == []


# ─────────────────────────────────────────────────────────────────────────────
# run (end to end, over the fake file-writing binary)
# ─────────────────────────────────────────────────────────────────────────────


class TestNiktoRun:
    def test_end_to_end_with_fake_binary(self, fake_nikto_on_path):
        adapter = NiktoAdapter()
        assert adapter.is_available() is True
        findings = adapter.run("http://app.local/", ScanContext(tool_timeout=30))
        assert len(findings) == 2

    def test_absent_binary_skips_cleanly(self, monkeypatch):
        monkeypatch.setattr(NiktoAdapter, "is_available", lambda self: False)
        assert NiktoAdapter().run("http://app.local/", ScanContext()) == []

    def test_no_output_file_returns_empty(self, tmp_path, monkeypatch):
        """A binary that exits without ever writing -output degrades to no findings."""
        script = tmp_path / "nikto"
        script.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(1)\n")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
        assert NiktoAdapter().run("http://app.local/", ScanContext(tool_timeout=10)) == []

    def test_cleans_up_its_temp_dir(self, fake_nikto_on_path):
        adapter = NiktoAdapter()
        adapter.run("http://app.local/", ScanContext(tool_timeout=30))
        assert not os.path.isdir(os.path.dirname(adapter._output_path))
