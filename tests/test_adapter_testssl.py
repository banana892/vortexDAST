"""
VortexDAST – tests/test_adapter_testssl.py
────────────────────────────────────────────────────────────────────────────
Tests for ``adapters/testssl_adapter.py``.

testssl.sh, like nikto, only writes JSON to a file (never stdout), so the
adapter overrides ``run()`` to pass it a temp path and read that back — the
end-to-end test uses a fake ``testssl.sh`` binary that writes canned JSON to
whatever path follows ``--jsonfile`` in its own argv. Hermetic: no real
testssl.sh, no network, no TLS connections to anything.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from adapters.testssl_adapter import TestsslAdapter
from core.orchestrator import ScanContext, discover_adapters
from modules.base import Confidence, Severity

# Modeled on real `testssl.sh --jsonfile` output: a mix of OK/INFO/WARN (must
# all be dropped) alongside real LOW/MEDIUM/HIGH/CRITICAL findings, one with
# a CVE/CWE pair.
_TESTSSL_JSON = json.dumps(
    [
        {"id": "cmdline_ip-target", "ip": "/", "port": "443", "severity": "WARN", "finding": "not a server name"},
        {"id": "heartbleed", "ip": "10.0.0.5/10.0.0.5", "port": "443", "severity": "OK",
         "cve": "CVE-2014-0160", "cwe": "CWE-119", "finding": "not vulnerable"},
        {"id": "cert_fingerprintSHA256", "ip": "10.0.0.5/10.0.0.5", "port": "443", "severity": "INFO",
         "finding": "890F6245..."},
        {"id": "cipherlist_OBSOLETED", "ip": "10.0.0.5/10.0.0.5", "port": "443", "severity": "LOW",
         "finding": "offered"},
        {"id": "security_headers", "ip": "10.0.0.5/10.0.0.5", "port": "443", "severity": "MEDIUM",
         "finding": "--"},
        {"id": "cert_revocation", "ip": "10.0.0.5/10.0.0.5", "port": "443", "severity": "HIGH",
         "finding": "Neither CRL nor OCSP URI provided"},
        {"id": "cert_chain_of_trust", "ip": "10.0.0.5/10.0.0.5", "port": "443", "severity": "CRITICAL",
         "finding": "failed (self signed)."},
        {"id": "ROBOT", "ip": "10.0.0.5/10.0.0.5", "port": "443", "severity": "LOW",
         "cve": "CVE-2017-13099 CVE-2017-6168", "cwe": "CWE-203", "finding": "potentially vulnerable"},
    ]
)

_FAKE_TESTSSL = r'''#!/usr/bin/env python3
import sys
out = sys.argv[sys.argv.index("--jsonfile") + 1]
with open(out, "w") as fh:
    fh.write(__PAYLOAD__)
sys.exit(1)
'''


def _write_fake_testssl(dir_path: Path, payload: str) -> Path:
    script = dir_path / "testssl.sh"
    script.write_text(_FAKE_TESTSSL.replace("__PAYLOAD__", repr(payload)))
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


@pytest.fixture
def fake_testssl_on_path(tmp_path, monkeypatch):
    """Put a fake ``testssl.sh`` first on PATH (shadowing any real install)."""
    _write_fake_testssl(tmp_path, _TESTSSL_JSON)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    return tmp_path


# ─────────────────────────────────────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────────────────────────────────────


def test_testssl_adapter_is_discovered():
    registry = discover_adapters()
    assert registry["testssl"] is TestsslAdapter


# ─────────────────────────────────────────────────────────────────────────────
# build_command
# ─────────────────────────────────────────────────────────────────────────────


class TestTestsslCommand:
    def test_argv_shape(self):
        adapter = TestsslAdapter()
        adapter._output_path = "/tmp/out.json"
        argv = adapter.build_command("https://app.local:8443/", ScanContext())
        assert argv[0] == "testssl.sh"
        assert argv[argv.index("--jsonfile") + 1] == "/tmp/out.json"
        assert argv[-1] == "https://app.local:8443/"

    def test_target_is_a_single_argv_element(self):
        evil = "https://app.local/;rm -rf ~"
        argv = TestsslAdapter().build_command(evil, ScanContext())
        assert argv.count(evil) == 1


# ─────────────────────────────────────────────────────────────────────────────
# parse
# ─────────────────────────────────────────────────────────────────────────────


class TestTestsslParse:
    def test_drops_ok_warn_and_info(self):
        findings = TestsslAdapter().parse(_TESTSSL_JSON)
        ids = {f.extra["testssl_id"] for f in findings}
        assert "cmdline_ip-target" not in ids  # WARN
        assert "heartbleed" not in ids  # OK
        assert "cert_fingerprintSHA256" not in ids  # INFO

    def test_maps_the_four_real_severities(self):
        findings = TestsslAdapter().parse(_TESTSSL_JSON)
        assert len(findings) == 5
        by_id = {f.extra["testssl_id"]: f for f in findings}
        assert by_id["cipherlist_OBSOLETED"].severity == Severity.LOW
        assert by_id["security_headers"].severity == Severity.MEDIUM
        assert by_id["cert_revocation"].severity == Severity.HIGH
        assert by_id["cert_chain_of_trust"].severity == Severity.CRITICAL

    def test_confidence_is_always_certain(self):
        findings = TestsslAdapter().parse(_TESTSSL_JSON)
        assert all(f.confidence == Confidence.CERTAIN for f in findings)

    def test_url_built_from_ip_and_port(self):
        findings = TestsslAdapter().parse(_TESTSSL_JSON)
        cert = next(f for f in findings if f.extra["testssl_id"] == "cert_chain_of_trust")
        assert cert.url == "10.0.0.5:443"

    def test_cve_and_cwe_surfaced_in_extra(self):
        findings = TestsslAdapter().parse(_TESTSSL_JSON)
        robot = next(f for f in findings if f.extra["testssl_id"] == "ROBOT")
        assert robot.extra["cve"] == "CVE-2017-13099 CVE-2017-6168"
        assert robot.extra["cwe"] == "CWE-203"
        assert "cve=" in robot.evidence

    def test_empty_or_malformed(self):
        assert TestsslAdapter().parse("") == []
        assert TestsslAdapter().parse("not json") == []
        assert TestsslAdapter().parse(json.dumps({"not": "a list"})) == []


# ─────────────────────────────────────────────────────────────────────────────
# run (end to end, over the fake file-writing binary)
# ─────────────────────────────────────────────────────────────────────────────


class TestTestsslRun:
    def test_end_to_end_with_fake_binary(self, fake_testssl_on_path):
        adapter = TestsslAdapter()
        assert adapter.is_available() is True
        findings = adapter.run("https://app.local/", ScanContext(tool_timeout=30))
        assert len(findings) == 5

    def test_tolerates_nonzero_exit_code(self, fake_testssl_on_path):
        """testssl.sh exits 1 when it has findings — not an error."""
        findings = TestsslAdapter().run("https://app.local/", ScanContext(tool_timeout=30))
        assert len(findings) == 5

    def test_absent_binary_skips_cleanly(self, monkeypatch):
        monkeypatch.setattr(TestsslAdapter, "is_available", lambda self: False)
        assert TestsslAdapter().run("https://app.local/", ScanContext()) == []

    def test_no_output_file_returns_empty(self, tmp_path, monkeypatch):
        script = tmp_path / "testssl.sh"
        script.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(1)\n")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
        assert TestsslAdapter().run("https://app.local/", ScanContext(tool_timeout=10)) == []

    def test_cleans_up_its_temp_dir(self, fake_testssl_on_path):
        adapter = TestsslAdapter()
        adapter.run("https://app.local/", ScanContext(tool_timeout=30))
        assert not os.path.isdir(os.path.dirname(adapter._output_path))
