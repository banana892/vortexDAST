"""
VortexDAST – tests/test_redirect_scope.py
Scope-aware redirect following: an off-scope 30x must never be followed, so a
hostile target cannot bounce a probe (params, body, cookies, auth header) onto
an unintended host. See core/requester.py Requester.set_scope_guard.
"""

from __future__ import annotations

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator, List, Tuple

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crawler import ScopeGuard
from core.requester import Requester


def _make_server(handler_cls: type[BaseHTTPRequestHandler]) -> Tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def two_servers() -> Iterator[Tuple[str, str, List[str]]]:
    """A target server that redirects, and an 'evil' off-scope server that
    records any path it is hit on."""
    evil_hits: List[str] = []

    class EvilHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            evil_hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(b"evil")

        def log_message(self, *a: object) -> None:
            pass

    evil_server, evil_netloc = _make_server(EvilHandler)

    class TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/start":
                # Relative, in-scope redirect — must be followed.
                self.send_response(302)
                self.send_header("Location", "/dest")
                self.end_headers()
            elif self.path == "/dest":
                self.send_response(200)
                self.send_header("Content-Length", "5")
                self.end_headers()
                self.wfile.write(b"final")
            elif self.path == "/escape":
                # Absolute, off-scope redirect — must NOT be followed.
                self.send_response(302)
                self.send_header("Location", f"http://{evil_netloc}/pwned")
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *a: object) -> None:
            pass

    target_server, target_netloc = _make_server(TargetHandler)

    yield target_netloc, evil_netloc, evil_hits

    target_server.shutdown()
    evil_server.shutdown()


def test_in_scope_redirect_is_followed(two_servers: Tuple[str, str, List[str]]) -> None:
    target_netloc, _evil_netloc, _hits = two_servers
    r = Requester(rate_limit_rps=0, max_retries=0)
    r.set_scope_guard(ScopeGuard(allowed_domains=[target_netloc]))
    resp, err = r.get(f"http://{target_netloc}/start")
    r.close()

    assert err is None
    assert resp is not None
    assert resp.status_code == 200
    assert resp.text == "final"


def test_off_scope_redirect_is_blocked(
    two_servers: Tuple[str, str, List[str]], caplog: pytest.LogCaptureFixture
) -> None:
    target_netloc, _evil_netloc, evil_hits = two_servers
    r = Requester(rate_limit_rps=0, max_retries=0)
    r.set_scope_guard(ScopeGuard(allowed_domains=[target_netloc]))

    with caplog.at_level("WARNING", logger="core.requester"):
        resp, err = r.get(f"http://{target_netloc}/escape")
    r.close()

    assert err is None
    assert resp is not None
    # The redirect itself is returned, unfollowed.
    assert resp.status_code == 302
    # The off-scope host was never contacted.
    assert evil_hits == []
    assert "Blocked off-scope redirect" in caplog.text


def test_without_guard_off_scope_redirect_is_followed(
    two_servers: Tuple[str, str, List[str]]
) -> None:
    """Regression guard: default (no scope guard) behaviour still follows any
    redirect, proving the scope guard is what blocks the escape above."""
    target_netloc, _evil_netloc, evil_hits = two_servers
    r = Requester(rate_limit_rps=0, max_retries=0)
    resp, err = r.get(f"http://{target_netloc}/escape")
    r.close()

    assert err is None
    assert resp is not None
    assert resp.status_code == 200
    assert resp.text == "evil"
    assert evil_hits == ["/pwned"]
