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
