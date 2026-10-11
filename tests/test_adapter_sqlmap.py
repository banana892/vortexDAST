"""
VortexDAST – tests/test_adapter_sqlmap.py
────────────────────────────────────────────────────────────────────────────
Tests for ``adapters/sqlmap_adapter.py``.

sqlmap is driven over HTTP (its REST API server), not a single blocking
subprocess call, so the end-to-end test replaces the ``sqlmapapi`` binary
with a fake one that is itself a tiny HTTP server replaying canned responses
shaped like the real REST API — hermetic: no real sqlmap, no network, no
scanning of anything.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from adapters.sqlmap_adapter import SqlmapAdapter
from core.orchestrator import ScanContext, discover_adapters
from modules.base import Confidence, Severity

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

# Modeled on a genuine /scan/<id>/data response: one confirmed injection point
# (GET parameter 'id', SQLite, four techniques) plus a non-TECHNIQUES entry
# that must be ignored.
_SCAN_DATA = {
    "success": True,
    "data": [
        {"status": 1, "type": 9, "type_name": "DBMS_FINGERPRINT", "value": "SQLite 3.9+"},
        {
            "status": 1,
            "type": 0,
            "type_name": "TECHNIQUES",
            "value": [
                {
                    "place": "GET",
                    "parameter": "id",
                    "dbms": "SQLite",
                    "dbms_version": [">= 3.9"],
                    "os": None,
                    "notes": [],
                    "data": [
                        {
                            "technique": "boolean-based blind",
                            "title": "AND boolean-based blind",
                            "payload": "id=1 AND 1=1",
                            "vector": "AND [INFERENCE]",
                        },
                        {
                            "technique": "error-based",
                            "title": "SQLite error-based",
                            "payload": "id=1 AND 1=CAST(...)",
                            "vector": None,
                        },
                    ],
                },
            ],
        },
    ],
    "error": [],
}

_FAKE_SQLMAPAPI_TEMPLATE = r'''#!/usr/bin/env python3
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[sys.argv.index("--port") + 1])
DATA = json.loads(__DATA_JSON__)
polls = {"n": 0}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/task/new":
            self._send({"success": True, "taskid": "t1"})
        elif self.path == "/scan/t1/status":
            polls["n"] += 1
            status = "running" if polls["n"] < 2 else "terminated"
            self._send({"success": True, "status": status, "returncode": None if status == "running" else 0})
        elif self.path == "/scan/t1/data":
            self._send(DATA)
        elif self.path == "/task/t1/delete":
            self._send({"success": True})
        else:
            self._send({"success": False}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if self.path == "/option/t1/set":
            self._send({"success": True})
        elif self.path == "/scan/t1/start":
            self._send({"success": True, "engineid": 1})
        else:
            self._send({"success": False}, 404)

HTTPServer(("127.0.0.1", port), Handler).serve_forever()
'''


def _write_fake_sqlmapapi(dir_path: Path, scan_data: dict) -> Path:
    """Write a fake ``sqlmapapi`` that serves ``scan_data`` from a real localhost socket."""
    script = dir_path / "sqlmapapi"
    source = _FAKE_SQLMAPAPI_TEMPLATE.replace(
        "__DATA_JSON__", json.dumps(json.dumps(scan_data))
    )
    script.write_text(source)
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


@pytest.fixture
def fake_sqlmapapi_on_path(tmp_path, monkeypatch):
    """Put a fake ``sqlmapapi`` first on PATH (shadowing any real sqlmap install)."""
    _write_fake_sqlmapapi(tmp_path, _SCAN_DATA)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    return tmp_path


# ─────────────────────────────────────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────────────────────────────────────


def test_sqlmap_adapter_is_discovered():
    registry = discover_adapters()
    assert registry["sqlmap"] is SqlmapAdapter


# ─────────────────────────────────────────────────────────────────────────────
# build_command
# ─────────────────────────────────────────────────────────────────────────────


class TestSqlmapCommand:
    def test_argv_starts_the_rest_api_server(self):
        adapter = SqlmapAdapter()
        argv = adapter.build_command("http://app.local/?id=1", ScanContext())
        assert argv[0] == "sqlmapapi"
        assert "-s" in argv
        assert argv[argv.index("--host") + 1] == "127.0.0.1"
        assert argv[argv.index("--port") + 1] == str(adapter.port)
        # Random per-instance credentials, never a fixed default.
        assert argv[argv.index("--username") + 1] == adapter.username
        assert argv[argv.index("--password") + 1] == adapter.password

    def test_target_never_appears_in_argv(self):
        """The target reaches sqlmap only over HTTP, never via argv/shell."""
        evil = "http://app.local/?id=1;rm -rf ~"
        argv = SqlmapAdapter().build_command(evil, ScanContext())
        assert evil not in argv

    def test_two_instances_get_different_ports_and_credentials(self):
        a, b = SqlmapAdapter(), SqlmapAdapter()
        assert a.port != b.port
        assert a.username != b.username
        assert a.password != b.password


# ─────────────────────────────────────────────────────────────────────────────
# parse
# ─────────────────────────────────────────────────────────────────────────────


class TestSqlmapParse:
    def test_maps_confirmed_injection(self):
        adapter = SqlmapAdapter()
        adapter._target = "http://app.local/?id=1"
        findings = adapter.parse(json.dumps(_SCAN_DATA))
        assert len(findings) == 1
        finding = findings[0]
        assert finding.title == "Confirmed SQL Injection: GET parameter 'id'"
        assert finding.severity == Severity.CRITICAL
        assert finding.confidence == Confidence.CERTAIN
        assert finding.url == "http://app.local/?id=1"
        assert finding.parameter == "id"
        assert finding.payload == "id=1 AND 1=1"
        assert finding.extra["tool"] == "sqlmap"
        assert finding.extra["dbms"] == "SQLite"
        assert finding.extra["techniques"] == ["boolean-based blind", "error-based"]
        assert "boolean-based blind" in finding.evidence

    def test_ignores_non_technique_content_types(self):
        only_fingerprint = {"success": True, "data": [_SCAN_DATA["data"][0]], "error": []}
        assert SqlmapAdapter().parse(json.dumps(only_fingerprint)) == []

    def test_empty_or_malformed_output(self):
        assert SqlmapAdapter().parse("") == []
        assert SqlmapAdapter().parse("not json") == []
        assert SqlmapAdapter().parse(json.dumps({"success": True, "data": []})) == []


# ─────────────────────────────────────────────────────────────────────────────
# run (end to end, over the fake REST API)
# ─────────────────────────────────────────────────────────────────────────────


class TestSqlmapRun:
    def test_end_to_end_with_fake_server(self, fake_sqlmapapi_on_path):
        adapter = SqlmapAdapter()
        assert adapter.is_available() is True
        findings = adapter.run("http://app.local/?id=1", ScanContext(tool_timeout=20))
        assert len(findings) == 1
        assert findings[0].parameter == "id"
        assert findings[0].url == "http://app.local/?id=1"

    def test_absent_binary_skips_cleanly(self, monkeypatch):
        monkeypatch.setattr(SqlmapAdapter, "is_available", lambda self: False)
        assert SqlmapAdapter().run("http://app.local/?id=1", ScanContext()) == []

    def test_no_findings_when_server_never_confirms_injection(self, tmp_path, monkeypatch):
        clean_data = {"success": True, "data": [], "error": []}
        _write_fake_sqlmapapi(tmp_path, clean_data)
        monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
        findings = SqlmapAdapter().run("http://app.local/?id=1", ScanContext(tool_timeout=20))
        assert findings == []
