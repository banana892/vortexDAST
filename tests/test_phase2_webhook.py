"""
VortexDAST – tests/test_phase2_webhook.py
Webhook scan summaries: payload shape, secret isolation, failure handling.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterator, List, Tuple

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.notify import build_payload, send_webhook
from modules.base import Confidence, Finding, Severity
from scanner import _build_parser, run_scan


def _f(title: str, sev: Severity, **kw: Any) -> Finding:
    return Finding(title=title, severity=sev, url=f"https://t.com/{title}",
                   evidence="DB_PASSWORD=hunter2", payload="probe-value", **kw)


def _findings() -> List[Finding]:
    return [
        _f("info", Severity.INFORMATIONAL),
        _f("crit", Severity.CRITICAL, confidence=Confidence.CERTAIN),
        _f("med", Severity.MEDIUM),
        _f("low", Severity.LOW),
    ]


def test_json_payload_counts_and_orders_by_severity() -> None:
    p = build_payload(_findings(), "https://t.com", "json", 2, {"threads": 10})
    assert p["summary"] == {"total": 4, "by_severity": {
        "critical": 1, "high": 0, "medium": 1, "low": 1, "informational": 1}}
    assert [f["title"] for f in p["findings"]] == ["crit", "med", "low", "info"]
    assert p["findings"][0]["confidence"] == "certain"
    assert p["exit_code"] == 2 and p["truncated"] is False
    assert p["text"] == "VortexDAST scan of https://t.com: 1 critical, 1 medium, 1 low, 1 informational."


def test_payloads_never_include_evidence_or_probe_values() -> None:
    for fmt in ("json", "slack"):
        body = json.dumps(build_payload(_findings(), "https://t.com", fmt, 2))
        assert "hunter2" not in body and "probe-value" not in body


def test_slack_payload_is_text_only_and_lists_medium_and_above() -> None:
    p = build_payload(_findings(), "https://t.com", "slack", 2)
    assert set(p) == {"text"}
    assert "[CRITICAL] crit" in p["text"] and "[MEDIUM] med" in p["text"]
    assert "[LOW]" not in p["text"]


def test_long_lists_are_truncated() -> None:
    many = [_f(f"f{i}", Severity.HIGH) for i in range(25)]
    assert len(build_payload(many, "t", "json", 2)["findings"]) == 20
    assert build_payload(many, "t", "json", 2)["truncated"] is True
    assert "…and 5 more" in build_payload(many, "t", "slack", 2)["text"]


def test_empty_scan_message() -> None:
    assert build_payload([], "https://t.com", "json", 0)["text"] == "VortexDAST scan of https://t.com: no findings."


# ── Real HTTP ────────────────────────────────────────────────────────────────


def _serve(handler_cls: type) -> Tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def webhook_sink() -> Iterator[Tuple[str, List[Dict[str, Any]]]]:
    received: List[Dict[str, Any]] = []

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            received.append({"path": self.path, "headers": dict(self.headers), "body": json.loads(body)})
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a: object) -> None:
            pass

    server, base = _serve(Sink)
    yield base, received
    server.shutdown()


@pytest.fixture
def target_site() -> Iterator[Tuple[str, List[Dict[str, str]]]]:
    seen: List[Dict[str, str]] = []

    class Site(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            seen.append(dict(self.headers))
            body = b"<html><body>hello</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a: object) -> None:
            pass

    server, base = _serve(Site)
    yield base + "/", seen
    server.shutdown()


def test_send_webhook_posts_json(webhook_sink: Any) -> None:
    base, received = webhook_sink
    assert send_webhook(base + "/hook", {"text": "hi"}) is True
    assert received[0]["body"] == {"text": "hi"}


def test_failed_webhook_logs_host_only(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING", logger="core.notify"):
        assert send_webhook("http://127.0.0.1:9/T000/B000/SECRETTOKEN", {"text": "x"}) is False
    assert "127.0.0.1:9" in caplog.text
    assert "SECRETTOKEN" not in caplog.text


def test_scan_posts_summary_without_target_credentials(webhook_sink: Any, target_site: str) -> None:
    base, received = webhook_sink
    target_url, target_seen = target_site
    args = _build_parser().parse_args([
        "-u", target_url, "-m", "headers_audit", "--max-depth", "0", "--rate-limit", "0",
        "-H", "Authorization: Bearer target-secret", "--cookie", "sid=target-session",
        "--webhook", base + "/hook",
    ])
    exit_code = run_scan(args)

    # The credentials really were in play for the target...
    assert any(h.get("Authorization") == "Bearer target-secret" for h in target_seen)
    assert any("sid=target-session" in h.get("Cookie", "") for h in target_seen)

    # ...and none of them reached the webhook.
    assert len(received) == 1
    hook = received[0]
    sent = json.dumps(hook)
    assert "target-secret" not in sent and "target-session" not in sent
    assert "Authorization" not in hook["headers"] and "Cookie" not in hook["headers"]
    assert hook["body"]["target"] == target_url
    assert hook["body"]["exit_code"] == exit_code
    assert hook["body"]["summary"]["total"] >= 1  # missing security headers


def test_invalid_webhook_scheme_aborts_before_scanning() -> None:
    args = _build_parser().parse_args(["-u", "http://127.0.0.1:9", "--webhook", "ftp://x/hook"])
    assert run_scan(args) == 1
