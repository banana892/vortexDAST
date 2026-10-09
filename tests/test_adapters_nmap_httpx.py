"""
VortexDAST – tests/test_adapters_nmap_httpx.py
────────────────────────────────────────────────────────────────────────────
Tests for the Phase B tier-1 adapters: ``adapters/nmap_adapter.py`` and
``adapters/httpx_adapter.py``.

As with the nuclei adapter, every test is hermetic: adapters run against fake
binaries (fixture scripts emitting canned output placed first on ``PATH``), so
no real nmap/httpx, no network, and no scanning of anything. The fake nmap
shadows any real nmap installed on the machine.
"""

from __future__ import annotations

import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from adapters.httpx_adapter import HttpxAdapter
from adapters.nmap_adapter import NmapAdapter
from core.orchestrator import ScanContext, discover_adapters
from modules.base import Confidence, Finding, Severity


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

# Modeled on genuine `nmap -Pn -T4 -oX -` output: one open risky service with
# version info, one open ordinary service, plus closed and filtered ports that
# must NOT become findings.
_NMAP_XML = textwrap.dedent(
    """\
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE nmaprun>
    <nmaprun scanner="nmap" args="nmap -Pn -T4 -oX - app.local" version="7.95">
    <host starttime="1" endtime="2"><status state="up" reason="user-set"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <hostnames><hostname name="app.local" type="user"/></hostnames>
    <ports>
    <port protocol="tcp" portid="5432"><state state="open" reason="syn-ack"/><service name="postgresql" product="PostgreSQL DB" version="9.6.0" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" method="table" conf="3"/></port>
    <port protocol="tcp" portid="22"><state state="closed" reason="reset"/><service name="ssh" method="table" conf="3"/></port>
    <port protocol="tcp" portid="3306"><state state="filtered" reason="no-response"/><service name="mysql" method="table" conf="3"/></port>
    </ports>
    </host>
    </nmaprun>
    """
)

_HTTPX_JSONL = textwrap.dedent(
    """\
    {"url":"https://app.local","input":"app.local","host":"10.0.0.5","port":"443","scheme":"https","status_code":200,"title":"App Home","webserver":"nginx/1.25","tech":["Nginx","React"]}
    {"url":"http://app.local:8080","status_code":302,"webserver":"Jetty","tech":"Java"}
    {"status_code":200,"title":"no url here"}
    not-valid-json-line
    """
)


def _write_fake_binary(dir_path: Path, name: str, stdout: str, exit_code: int = 0) -> Path:
    """Create an executable script that prints ``stdout`` and exits."""
    script = dir_path / name
    script.write_text(
        "#!/usr/bin/env bash\n"
        "cat <<'VORTEX_EOF'\n"
        f"{stdout}"
        "VORTEX_EOF\n"
        f"exit {exit_code}\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


@pytest.fixture
def fake_tools_on_path(tmp_path, monkeypatch):
    """Put fake ``nmap`` and ``httpx`` first on PATH (shadowing real ones)."""
    _write_fake_binary(tmp_path, "nmap", _NMAP_XML)
    _write_fake_binary(tmp_path, "httpx", _HTTPX_JSONL)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    return tmp_path


# ─────────────────────────────────────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────────────────────────────────────


def test_tier1_adapters_are_discovered():
    registry = discover_adapters()
    assert registry["nmap"] is NmapAdapter
    assert registry["httpx"] is HttpxAdapter
    assert "nuclei" in registry


# ─────────────────────────────────────────────────────────────────────────────
# NmapAdapter
# ─────────────────────────────────────────────────────────────────────────────


class TestNmapCommand:
    def test_extracts_host_from_url(self):
        argv = NmapAdapter().build_command("https://app.local:8443/login?x=1", ScanContext())
        assert argv[0] == "nmap"
        assert argv[-1] == "app.local"
        # Structured XML to stdout.
        i = argv.index("-oX")
        assert argv[i + 1] == "-"

    def test_bare_host_passes_through(self):
        argv = NmapAdapter().build_command("10.0.0.5", ScanContext())
        assert argv[-1] == "10.0.0.5"

    def test_hostile_target_is_one_argv_element(self):
        """A shell-metachar target stays a single literal argv element."""
        evil = "app.local;rm -rf ~"
        argv = NmapAdapter().build_command(evil, ScanContext())
        assert argv[-1] == evil
        assert argv.count(evil) == 1


class TestNmapParse:
    def test_only_open_ports_become_findings(self):
        findings = NmapAdapter().parse(_NMAP_XML)
        ports = sorted(f.extra["port"] for f in findings)
        # 22 is closed and 3306 is filtered — neither is reported.
        assert ports == [443, 5432]

    def test_risky_service_is_medium_with_version(self):
        findings = NmapAdapter().parse(_NMAP_XML)
        pg = next(f for f in findings if f.extra["port"] == 5432)
        assert pg.severity == Severity.MEDIUM
        assert pg.confidence == Confidence.CERTAIN
        assert pg.title == "Exposed Service: postgresql (tcp/5432)"
        assert pg.url == "10.0.0.5:5432"
        assert pg.extra["tool"] == "nmap"
        assert pg.extra["product"] == "PostgreSQL DB 9.6.0"
        assert "PostgreSQL DB 9.6.0" in pg.evidence

    def test_ordinary_service_is_informational(self):
        findings = NmapAdapter().parse(_NMAP_XML)
        web = next(f for f in findings if f.extra["port"] == 443)
        assert web.severity == Severity.INFORMATIONAL
        assert web.title == "Open Port: https (tcp/443)"
        assert web.extra["product"] is None

    def test_prefers_ip_address_over_mac(self):
        findings = NmapAdapter().parse(_NMAP_XML)
        assert all(f.extra["host"] == "10.0.0.5" for f in findings)

    def test_malformed_xml_returns_empty(self):
        assert NmapAdapter().parse("<nmaprun><host>") == []

    def test_empty_output_returns_empty(self):
        assert NmapAdapter().parse("") == []
        assert NmapAdapter().parse("   \n") == []


class TestNmapRun:
    def test_end_to_end_with_fake_binary(self, fake_tools_on_path):
        adapter = NmapAdapter()
        assert adapter.is_available() is True
        findings = adapter.run("https://app.local", ScanContext())
        assert sorted(f.extra["port"] for f in findings) == [443, 5432]

    def test_falls_back_to_builtin_port_scan_when_absent(self, monkeypatch):
        """No nmap → the built-in TCP port scan runs instead (no network)."""
        canned = Finding(
            title="Open Port: http (tcp/80)",
            severity=Severity.INFORMATIONAL,
            url="app.local:80",
            extra={"module": "port_scan", "host": "app.local", "port": 80},
        )
        seen = {}

        def fake_run(self, endpoint):
            seen["url"] = endpoint.url
            return [canned]

        monkeypatch.setattr(NmapAdapter, "is_available", lambda self: False)
        monkeypatch.setattr("modules.port_scan.PortScanModule.run", fake_run)

        findings = NmapAdapter().run("https://app.local", ScanContext())

        assert seen["url"] == "https://app.local"
        assert findings == [canned]
        # Tagged with the orchestration path, port_scan metadata preserved.
        assert findings[0].extra["tool"] == "nmap"
        assert findings[0].extra["via"] == "port_scan_fallback"
        assert findings[0].extra["module"] == "port_scan"

    def test_fallback_uses_requester_from_context(self, monkeypatch):
        captured = {}
        sentinel = object()

        def fake_init(self, requester):
            captured["requester"] = requester
            self._scanned_hosts = set()

        monkeypatch.setattr(NmapAdapter, "is_available", lambda self: False)
        monkeypatch.setattr("modules.port_scan.PortScanModule.__init__", fake_init)
        monkeypatch.setattr("modules.port_scan.PortScanModule.run", lambda self, ep: [])

        ctx = ScanContext()
        ctx.extra["requester"] = sentinel
        NmapAdapter().run("https://app.local", ctx)
        assert captured["requester"] is sentinel


# ─────────────────────────────────────────────────────────────────────────────
# HttpxAdapter
# ─────────────────────────────────────────────────────────────────────────────


class TestHttpxCommand:
    def test_build_command_is_argv_list_with_json(self):
        argv = HttpxAdapter().build_command("https://app.local", ScanContext())
        assert argv[0] == "httpx"
        assert "-json" in argv
        assert argv.count("https://app.local") == 1


class TestHttpxParse:
    def test_maps_records_and_skips_bad_ones(self):
        findings = HttpxAdapter().parse(_HTTPX_JSONL)
        # Two records with a URL; the url-less record and the bad line are skipped.
        assert [f.url for f in findings] == ["https://app.local", "http://app.local:8080"]

    def test_finding_is_informational_with_fingerprint(self):
        home = HttpxAdapter().parse(_HTTPX_JSONL)[0]
        assert home.severity == Severity.INFORMATIONAL
        assert home.confidence == Confidence.CERTAIN
        assert home.title == "Live HTTP service: https://app.local"
        assert home.extra["tool"] == "httpx"
        assert home.extra["status_code"] == 200
        assert home.extra["webserver"] == "nginx/1.25"
        assert home.extra["tech"] == ["Nginx", "React"]
        assert "status=200" in home.evidence
        assert "tech=Nginx,React" in home.evidence

    def test_string_tech_is_normalised_to_list(self):
        jetty = HttpxAdapter().parse(_HTTPX_JSONL)[1]
        assert jetty.extra["tech"] == ["Java"]
        assert jetty.extra["title"] is None

    def test_exposes_service_url_for_chaining(self):
        findings = HttpxAdapter().parse(_HTTPX_JSONL)
        assert [f.extra["http_service_url"] for f in findings] == [
            "https://app.local",
            "http://app.local:8080",
        ]

    def test_empty_output(self):
        assert HttpxAdapter().parse("") == []


class TestHttpxRun:
    def test_end_to_end_with_fake_binary(self, fake_tools_on_path):
        adapter = HttpxAdapter()
        assert adapter.is_available() is True
        findings = adapter.run("https://app.local", ScanContext())
        assert len(findings) == 2

    def test_absent_binary_skips_cleanly(self, monkeypatch):
        monkeypatch.setattr(HttpxAdapter, "is_available", lambda self: False)
        assert HttpxAdapter().run("https://app.local", ScanContext()) == []
