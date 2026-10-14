"""
VortexDAST – tests/test_phase2_throttling.py
Adaptive rate limiting when the target answers HTTP 429 / 503+Retry-After.
"""

from __future__ import annotations

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator, List

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.requester import Requester


def _req(rps: float = 5.0) -> Requester:
    return Requester(rate_limit_rps=rps, max_retries=0)


def test_429_doubles_interval() -> None:
    r = _req(5.0)
    r._record_status(429, {})
    assert r._min_interval == pytest.approx(0.4)
    assert r.throttle_events == 1


def test_interval_is_capped() -> None:
    r = _req(5.0)
    for _ in range(20):
        r._record_status(429, {})
    assert r._min_interval == Requester._THROTTLE_MAX_INTERVAL


def test_throttling_enables_limiter_when_disabled() -> None:
    r = _req(0)
    r._record_status(429, {})
    assert r._min_interval == Requester._THROTTLE_FLOOR_INTERVAL


def test_503_counts_only_with_retry_after() -> None:
    r = _req(5.0)
    r._record_status(503, {})
    assert r.throttle_events == 0
    r._record_status(503, {"Retry-After": "2"})
    assert r.throttle_events == 1


def test_plain_403_is_not_throttling() -> None:
    r = _req(5.0)
    r._record_status(403, {"Content-Type": "text/html"})
    assert r.throttle_events == 0
    assert r._min_interval == pytest.approx(0.2)


def test_cloudflare_edge_block_is_throttling(caplog: pytest.LogCaptureFixture) -> None:
    r = _req(5.0)
    with caplog.at_level("WARNING", logger="core.requester"):
        r._record_status(403, {"CF-RAY": "abc123-SJC", "Server": "cloudflare"})
    assert r.throttle_events == 1
    assert r._min_interval == pytest.approx(0.4)
    assert "CDN/WAF edge block" in caplog.text


def test_vercel_edge_block_is_throttling() -> None:
    r = _req(5.0)
    r._record_status(403, {"x-vercel-id": "sfo1::abcde-123"})
    assert r.throttle_events == 1


def test_waf_edge_block_recovers_like_any_other_throttle() -> None:
    r = _req(5.0)
    r._record_status(403, {"CF-RAY": "abc123-SJC"})
    for _ in range(Requester._RECOVERY_STREAK):
        r._record_status(200, {})
    assert r._min_interval == pytest.approx(0.2)


# ── Retry-After value parsing ───────────────────────────────────────────────


def test_retry_after_delta_seconds_overrides_the_doubling_ceiling() -> None:
    r = _req(5.0)
    r._record_status(429, {"Retry-After": "10"})
    assert r._min_interval == pytest.approx(10.0)


def test_retry_after_http_date_is_parsed() -> None:
    from datetime import datetime, timedelta, timezone
    from email.utils import format_datetime

    r = _req(5.0)
    future = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=5))
    r._record_status(429, {"Retry-After": future})
    assert r._min_interval == pytest.approx(5.0, abs=1.5)


def test_retry_after_is_capped() -> None:
    r = _req(5.0)
    r._record_status(429, {"Retry-After": "99999"})
    assert r._min_interval == Requester._MAX_RETRY_AFTER_WAIT


def test_retry_after_in_the_past_is_ignored() -> None:
    r = _req(5.0)
    r._record_status(429, {"Retry-After": "0"})
    assert r._min_interval == pytest.approx(0.4)


def test_retry_after_garbage_is_ignored() -> None:
    r = _req(5.0)
    r._record_status(429, {"Retry-After": "not-a-date"})
    assert r._min_interval == pytest.approx(0.4)


def test_parse_retry_after_directly() -> None:
    assert Requester._parse_retry_after(None) is None
    assert Requester._parse_retry_after("0") is None
    assert Requester._parse_retry_after("-5") is None
    assert Requester._parse_retry_after("3") == pytest.approx(3.0)
    assert Requester._parse_retry_after("bogus") is None


def test_recovers_to_configured_rate() -> None:
    r = _req(5.0)
    for _ in range(3):
        r._record_status(429, {})
    assert r._min_interval == pytest.approx(1.6)
    for _ in range(Requester._RECOVERY_STREAK * 3):
        r._record_status(200, {})
    assert r._min_interval == pytest.approx(0.2)


def test_recovers_to_unlimited_when_originally_disabled() -> None:
    r = _req(0)
    r._record_status(429, {})
    for _ in range(Requester._RECOVERY_STREAK):
        r._record_status(200, {})
    assert r._min_interval == 0


def test_no_recovery_drift_below_configured_rate() -> None:
    r = _req(5.0)
    for _ in range(Requester._RECOVERY_STREAK * 2):
        r._record_status(200, {})
    assert r._min_interval == pytest.approx(0.2)


# ── Against a real HTTP server ──────────────────────────────────────────────


@pytest.fixture
def throttling_server() -> Iterator[str]:
    statuses: List[int] = [429, 429, 200]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            code = statuses.pop(0) if statuses else 200
            self.send_response(code)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()


def test_real_429_responses_slow_the_requester(throttling_server: str, caplog: pytest.LogCaptureFixture) -> None:
    r = _req(50.0)
    with caplog.at_level("WARNING", logger="core.requester"):
        codes = [r.get(throttling_server)[0].status_code for _ in range(3)]
    assert codes == [429, 429, 200]
    assert r.throttle_events == 2
    assert r._min_interval == pytest.approx(0.4)
    assert "Target is throttling" in caplog.text
    r.close()
