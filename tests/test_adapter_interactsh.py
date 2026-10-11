"""
VortexDAST – tests/test_adapter_interactsh.py
────────────────────────────────────────────────────────────────────────────
Tests for ``adapters/interactsh_adapter.py``.

Like sqlmap, interactsh-client is a long-running process, not a one-shot
subprocess — so the end-to-end test replaces it with a fake binary that
mimics the real one closely enough for the adapter's own logic: it reads the
``-psf``/``-o`` paths and ``-n`` count off argv, writes that many fake
correlation domains to the payload file, then (to simulate an async
server-side callback landing moments later) appends one canned interaction
record to the interactions file for the *first* domain only. A tiny local
HTTP server stands in for the scanned target, so the test can also assert
exactly which parameter's probe request actually went out. Hermetic: no real
interactsh-client, no real OAST server, no scanning of anything.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from adapters.interactsh_adapter import InteractshAdapter
from core.orchestrator import ScanContext, discover_adapters
from modules.base import Confidence, Severity

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

_FAKE_CLIENT_TEMPLATE = r'''#!/usr/bin/env python3
import sys, time

def arg(flag):
    return sys.argv[sys.argv.index(flag) + 1]

psf = arg("-psf")
out = arg("-o")
n = int(arg("-n"))

domains = [f"fakeid{i}.test" for i in range(n)]
with open(psf, "w") as fh:
    fh.write("\n".join(domains) + "\n")

time.sleep(0.5)
with open(out, "a") as fh:
    fh.write('{"protocol":"http","unique-id":"fakeid0","full-id":"fakeid0","remote-address":"203.0.113.9","raw-request":"GET / HTTP/1.1","raw-response":"HTTP/1.1 200 OK","timestamp":"2026-01-01T00:00:00Z"}\n')
    fh.write('{"protocol":"dns","unique-id":"fakeid0","full-id":"fakeid0","remote-address":"203.0.113.10","raw-request":"","raw-response":"","timestamp":"2026-01-01T00:00:01Z"}\n')

while True:
    time.sleep(1)
'''


def _write_fake_client(dir_path: Path) -> Path:
    script = dir_path / "interactsh-client"
    script.write_text(_FAKE_CLIENT_TEMPLATE)
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


@pytest.fixture
def fake_client_on_path(tmp_path, monkeypatch):
    """Put a fake ``interactsh-client`` first on PATH (shadowing any real install)."""
    _write_fake_client(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    return tmp_path


class _RecordingHandler(BaseHTTPRequestHandler):
    """Target stand-in: records every request's query params, answers 200."""

    seen: list

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.seen.append(parse_qs(urlsplit(self.path).query))
        self.send_response(200)
        self.end_headers()


@pytest.fixture
def recording_target():
    """A tiny local HTTP server; yields (base_url, seen_requests_list)."""
    seen: list = []
    handler = type("Handler", (_RecordingHandler,), {"seen": seen})
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen
    finally:
        server.shutdown()


# ─────────────────────────────────────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────────────────────────────────────


def test_interactsh_adapter_is_discovered():
    registry = discover_adapters()
    assert registry["interactsh"] is InteractshAdapter


# ─────────────────────────────────────────────────────────────────────────────
# Parameter extraction / probe construction
# ─────────────────────────────────────────────────────────────────────────────


class TestExtractParams:
    def test_extracts_distinct_param_names_in_order(self):
        params = InteractshAdapter._extract_params("http://x/?a=1&b=2&a=3")
        assert params == ["a", "b"]

    def test_no_query_string_yields_empty(self):
        assert InteractshAdapter._extract_params("http://x/") == []


class TestBuildCommand:
    def test_argv_shape(self):
        adapter = InteractshAdapter()
        adapter._n = 2
        adapter._payload_file = "/tmp/p.txt"
        adapter._interactions_file = "/tmp/i.jsonl"
        argv = adapter.build_command("http://x/?a=1&b=2", ScanContext())
        assert argv[0] == "interactsh-client"
        assert argv[argv.index("-n") + 1] == "2"
        assert argv[argv.index("-psf") + 1] == "/tmp/p.txt"
        assert argv[argv.index("-o") + 1] == "/tmp/i.jsonl"


# ─────────────────────────────────────────────────────────────────────────────
# parse
# ─────────────────────────────────────────────────────────────────────────────


class TestParse:
    def test_groups_by_domain_and_prefers_http_confidence(self):
        adapter = InteractshAdapter()
        adapter._target = "http://app.local/?callback=x"
        adapter._domain_to_param = {"fakeid0": "callback"}
        raw = (
            '{"protocol":"dns","unique-id":"fakeid0","remote-address":"1.2.3.4"}\n'
            '{"protocol":"http","unique-id":"fakeid0","remote-address":"1.2.3.5"}\n'
        )
        findings = adapter.parse(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f.parameter == "callback"
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.CERTAIN
        assert f.url == "http://app.local/?callback=x"
        assert f.extra["protocols"] == ["dns", "http"]
        assert f.extra["interaction_count"] == 2

    def test_dns_only_is_firm_not_certain(self):
        adapter = InteractshAdapter()
        adapter._domain_to_param = {"fakeid0": "q"}
        findings = adapter.parse('{"protocol":"dns","unique-id":"fakeid0"}\n')
        assert findings[0].confidence == Confidence.FIRM

    def test_unmapped_domain_still_produces_a_finding(self):
        """A callback for a domain we lost track of is still real evidence."""
        adapter = InteractshAdapter()
        adapter._domain_to_param = {}
        findings = adapter.parse('{"protocol":"http","unique-id":"unknown"}\n')
        assert len(findings) == 1
        assert findings[0].parameter == "?"

    def test_empty_or_malformed(self):
        adapter = InteractshAdapter()
        assert adapter.parse("") == []
        assert adapter.parse("not json\n") == []


# ─────────────────────────────────────────────────────────────────────────────
# run (end to end, over the fake client + a real local target)
# ─────────────────────────────────────────────────────────────────────────────


class TestRun:
    def test_end_to_end_attributes_finding_to_right_param(
        self, fake_client_on_path, recording_target, monkeypatch
    ):
        # Real OOB callbacks are async, hence the adapter's grace period —
        # shrink it here so the test doesn't pay that wait for no reason.
        monkeypatch.setattr("adapters.interactsh_adapter._SETTLE_SECONDS", 1.0)
        base, seen = recording_target
        adapter = InteractshAdapter()
        target = f"{base}/?callback=orig&name=bob"
        findings = adapter.run(target, ScanContext(tool_timeout=30))

        assert len(findings) == 1
        assert findings[0].parameter == "callback"
        assert findings[0].url == target

        # Exactly one probe per parameter (2 params → 2 requests), and the
        # probe for 'callback' carried an interactsh-looking URL while
        # 'name' was left at its original request's untouched value.
        assert len(seen) == 2
        callback_probes = [q for q in seen if q.get("callback", [""])[0].startswith("http://fakeid")]
        assert len(callback_probes) == 1
        assert callback_probes[0]["name"] == ["bob"]

    def test_no_params_returns_empty_without_starting_client(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            "subprocess.Popen", lambda *a, **k: calls.append(a) or pytest.fail("should not start")
        )
        assert InteractshAdapter().run("http://app.local/", ScanContext()) == []
        assert calls == []

    def test_absent_binary_skips_cleanly(self, monkeypatch):
        monkeypatch.setattr(InteractshAdapter, "is_available", lambda self: False)
        assert InteractshAdapter().run("http://app.local/?a=1", ScanContext()) == []
