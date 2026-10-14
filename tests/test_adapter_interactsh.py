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
    """Target stand-in: records every GET's query params and every POST's body, answers 200."""

    seen: list
    seen_posts: list

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.seen.append(parse_qs(urlsplit(self.path).query))
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        self.seen_posts.append({"content_type": self.headers.get("Content-Type"), "body": body})
        self.send_response(200)
        self.end_headers()


@pytest.fixture
def recording_target():
    """A tiny local HTTP server; yields (base_url, seen_gets, seen_posts)."""
    seen: list = []
    seen_posts: list = []
    handler = type("Handler", (_RecordingHandler,), {"seen": seen, "seen_posts": seen_posts})
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen, seen_posts
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
        adapter._domain_to_combo = {"fakeid0": ("callback", "ssrf")}
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
        adapter._domain_to_combo = {"fakeid0": ("q", "ssrf")}
        findings = adapter.parse('{"protocol":"dns","unique-id":"fakeid0"}\n')
        assert findings[0].confidence == Confidence.FIRM

    def test_unmapped_domain_still_produces_a_finding(self):
        """A callback for a domain we lost track of is still real evidence."""
        adapter = InteractshAdapter()
        adapter._domain_to_combo = {}
        findings = adapter.parse('{"protocol":"http","unique-id":"unknown"}\n')
        assert len(findings) == 1
        assert findings[0].parameter == "?"

    def test_empty_or_malformed(self):
        adapter = InteractshAdapter()
        assert adapter.parse("") == []
        assert adapter.parse("not json\n") == []

    @pytest.mark.parametrize(
        "kind,expected_severity",
        [
            ("rce", Severity.CRITICAL),
            ("sqli_mssql", Severity.CRITICAL),
            ("sqli_oracle", Severity.CRITICAL),
            ("xxe", Severity.CRITICAL),
        ],
    )
    def test_each_vuln_kind_maps_to_a_distinct_finding(self, kind, expected_severity):
        adapter = InteractshAdapter()
        adapter._target = "http://app.local/?q=x"
        adapter._domain_to_combo = {"fakeid0": ("q", kind)}
        findings = adapter.parse('{"protocol":"dns","unique-id":"fakeid0"}\n')
        assert len(findings) == 1
        assert findings[0].severity == expected_severity
        assert findings[0].extra["vuln_class"] == kind

    def test_xxe_finding_has_no_real_parameter(self):
        """XXE has no query parameter at all — the <xml body> placeholder shows up instead."""
        adapter = InteractshAdapter()
        adapter._target = "http://app.local/api"
        adapter._domain_to_combo = {"fakeid0": ("<xml body>", "xxe")}
        findings = adapter.parse('{"protocol":"http","unique-id":"fakeid0"}\n')
        assert len(findings) == 1
        assert findings[0].parameter == "<xml body>"


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
        base, seen, seen_posts = recording_target
        adapter = InteractshAdapter()
        target = f"{base}/?callback=orig&name=bob"
        findings = adapter.run(target, ScanContext(tool_timeout=30))

        assert len(findings) == 1
        assert findings[0].parameter == "callback"
        assert findings[0].url == target
        assert findings[0].extra["vuln_class"] == "ssrf"

        # One GET per (parameter, payload-spec) combo: 2 params × 5 specs
        # (ssrf, 2×rce, 2×sqli) = 10 requests. Only the first combo built for
        # 'callback' uses the plain-URL (ssrf) payload, so exactly one
        # request carries an interactsh-looking URL in 'callback' while
        # 'name' stays at its original request's untouched value.
        assert len(seen) == 10
        callback_probes = [q for q in seen if q.get("callback", [""])[0].startswith("http://fakeid")]
        assert len(callback_probes) == 1
        assert callback_probes[0]["name"] == ["bob"]

        # Plus exactly one XXE POST, unrelated to either query parameter.
        assert len(seen_posts) == 1
        assert seen_posts[0]["content_type"] == "application/xml"
        assert "<!ENTITY xxe SYSTEM \"http://fakeid" in seen_posts[0]["body"]

    def test_no_params_still_runs_the_xxe_probe(
        self, fake_client_on_path, recording_target, monkeypatch
    ):
        """No query parameters at all — only the parameter-independent XXE probe fires."""
        monkeypatch.setattr("adapters.interactsh_adapter._SETTLE_SECONDS", 1.0)
        base, seen, seen_posts = recording_target
        adapter = InteractshAdapter()
        findings = adapter.run(base + "/", ScanContext(tool_timeout=30))

        assert seen == []  # no GET probes — nothing to substitute into
        assert len(seen_posts) == 1
        assert seen_posts[0]["content_type"] == "application/xml"
        assert len(findings) == 1
        assert findings[0].extra["vuln_class"] == "xxe"
        assert findings[0].parameter == "<xml body>"

    def test_absent_binary_skips_cleanly(self, monkeypatch):
        monkeypatch.setattr(InteractshAdapter, "is_available", lambda self: False)
        assert InteractshAdapter().run("http://app.local/?a=1", ScanContext()) == []


# ─────────────────────────────────────────────────────────────────────────────
# run — probing beyond query parameters (ctx.extra["endpoints"]): POST form
# fields and JSON body leaves, reusing core/json_fuzz.py like every other
# module already fuzzing captured JSON requests.
# ─────────────────────────────────────────────────────────────────────────────


class TestRunWithCrawledEndpoint:
    def test_probes_post_form_fields_too(self, fake_client_on_path, recording_target, monkeypatch):
        from core.crawler import CrawledEndpoint
        from core.parser import FormField, ParsedForm

        monkeypatch.setattr("adapters.interactsh_adapter._SETTLE_SECONDS", 1.0)
        base, seen, seen_posts = recording_target
        target = f"{base}/"
        endpoint = CrawledEndpoint(
            url=target,
            status_code=200,
            depth=0,
            forms=[
                ParsedForm(
                    action_url=target,
                    method="POST",
                    fields=[
                        FormField(name="username", field_type="text", default_value="bob"),
                        FormField(name="comment", field_type="text", default_value="hi"),
                    ],
                )
            ],
        )
        ctx = ScanContext(tool_timeout=30, extra={"endpoints": [endpoint]})
        findings = InteractshAdapter().run(target, ctx)

        form_findings = [f for f in findings if f.parameter in ("username", "comment")]
        assert len(form_findings) == 1  # only the fake client's one canned callback

        # No query parameters at all, so no GET probes.
        assert seen == []
        # Two fields × 5 payload specs = 10 form-encoded POSTs, plus the one
        # parameter-independent XXE POST (application/xml) — distinguishable
        # by content type.
        form_posts = [p for p in seen_posts if p["content_type"] != "application/xml"]
        assert len(form_posts) == 10
        assert any("username=http%3A%2F%2Ffakeid" in p["body"] for p in form_posts)
        # The untouched field keeps its original value on every probe.
        assert all("comment=hi" in p["body"] for p in form_posts if "username=http" in p["body"])

    def test_probes_json_body_leaves_too(self, fake_client_on_path, recording_target, monkeypatch):
        from core.crawler import CapturedJsonRequest, CrawledEndpoint

        monkeypatch.setattr("adapters.interactsh_adapter._SETTLE_SECONDS", 1.0)
        base, seen, seen_posts = recording_target
        target = f"{base}/"
        captured = CapturedJsonRequest(
            url=f"{base}/api/widgets", method="POST", body={"name": "gadget", "qty": 3}
        )
        endpoint = CrawledEndpoint(
            url=target, status_code=200, depth=0, json_requests=[captured]
        )
        ctx = ScanContext(tool_timeout=30, extra={"endpoints": [endpoint]})
        findings = InteractshAdapter().run(target, ctx)

        json_findings = [f for f in findings if f.parameter.startswith("body:")]
        assert len(json_findings) == 1

        assert seen == []
        # Two scalar leaves (name, qty) × 5 specs = 10 JSON POSTs.
        json_posts = [p for p in seen_posts if p["content_type"] == "application/json"]
        assert len(json_posts) == 10
        assert any("fakeid" in p["body"] for p in json_posts)

    def test_mismatched_endpoint_url_contributes_nothing(
        self, fake_client_on_path, recording_target, monkeypatch
    ):
        """An endpoint for a *different* URL must not leak its forms in here."""
        from core.crawler import CrawledEndpoint
        from core.parser import FormField, ParsedForm

        monkeypatch.setattr("adapters.interactsh_adapter._SETTLE_SECONDS", 1.0)
        base, seen, seen_posts = recording_target
        target = f"{base}/"
        other_endpoint = CrawledEndpoint(
            url=f"{base}/other",
            status_code=200,
            depth=0,
            forms=[
                ParsedForm(
                    action_url=f"{base}/other",
                    method="POST",
                    fields=[FormField(name="x", field_type="text", default_value="1")],
                )
            ],
        )
        ctx = ScanContext(tool_timeout=30, extra={"endpoints": [other_endpoint]})
        findings = InteractshAdapter().run(target, ctx)

        # Only the parameter-independent XXE probe should have run.
        assert seen == []
        assert len(seen_posts) == 1
        assert seen_posts[0]["content_type"] == "application/xml"
        assert len(findings) == 1
        assert findings[0].extra["vuln_class"] == "xxe"
