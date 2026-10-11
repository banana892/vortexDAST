"""
VortexDAST – tests/test_dom_watcher.py
────────────────────────────────────────────────────────────────────────────
Tests for ``core/dom_watcher.py`` — the headless-Playwright dynamic crawler.

Playwright + Chromium are a core dependency (not an optional external tool
like the adapters), so these run against a *real* headless browser and a
real local HTTP server serving a fake SPA whose links/forms only exist after
its inline ``<script>`` runs — the exact gap this module exists to close.
CI installs the Chromium binary via ``playwright install chromium`` before
running the suite (see ``.github/workflows/ci.yml``).

The one thing that's faked is Playwright's *absence*, via a ``sys.modules``
trick, so the "not installed" degrade path doesn't need an actual uninstall.
"""

from __future__ import annotations

import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crawler import ScopeGuard
from core.dom_watcher import DomWatcher
from core.parser import HTMLParser

# ─────────────────────────────────────────────────────────────────────────────
# Fixture SPA
# ─────────────────────────────────────────────────────────────────────────────

# seed(0) renders: /about, /page2, an off-scope link (different port — a
# different netloc, so ScopeGuard rejects it without any DNS trickery), and
# /hang (same origin, in scope, but the server never responds — exercises
# the navigation-timeout → failed_urls path for real, not mocked).
# page2(1) renders a link to page3(2), which renders a link to page4(3) —
# used to prove max_depth actually stops the crawl before page4.
_PAGES = {
    "/": """<!DOCTYPE html><html><body><div id="root"></div><script>
        document.getElementById('root').innerHTML = `
          <a href="/about">About</a>
          <a href="/page2">Page2</a>
          <a href="__OFFSCOPE__">Offscope</a>
          <a href="/hang">Dead</a>
          <form action="/api/search" method="GET">
            <input type="text" name="q" value="">
          </form>`;
        </script></body></html>""",
    "/about": """<!DOCTYPE html><html><body><div id="root"></div><script>
        document.getElementById('root').innerHTML = '<p>about, no links</p>';
        </script></body></html>""",
    "/page2": """<!DOCTYPE html><html><body><div id="root"></div><script>
        document.getElementById('root').innerHTML = '<a href="/page3">Page3</a>';
        </script></body></html>""",
    "/page3": """<!DOCTYPE html><html><body><div id="root"></div><script>
        document.getElementById('root').innerHTML = '<a href="/page4">Page4</a>';
        </script></body></html>""",
    "/page4": """<!DOCTYPE html><html><body>unreachable at max_depth=2</body></html>""",
}


def _make_handler(offscope_url: str):
    from http.server import BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.rstrip("/") or "/"
            if path == "/hang":
                # Never respond — the client's own navigation timeout fires
                # well before this returns (kept short so a daemon thread
                # possibly still sleeping past test teardown is negligible).
                time.sleep(5)
                return
            body = _PAGES.get(path, "<html><body>404</body></html>")
            body = body.replace("__OFFSCOPE__", offscope_url)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

    return Handler


@pytest.fixture
def spa_server():
    """A local HTTP server serving the fixture SPA; yields its base URL."""
    from http.server import ThreadingHTTPServer

    # Threaded: a page that hangs (below) must not block other in-flight
    # navigations against the same server.
    offscope_server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(""))
    offscope_thread = threading.Thread(target=offscope_server.serve_forever, daemon=True)
    offscope_thread.start()
    offscope_url = f"http://127.0.0.1:{offscope_server.server_port}/"

    handler = _make_handler(offscope_url)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        offscope_server.shutdown()


# ─────────────────────────────────────────────────────────────────────────────
# Sanity: the static parser genuinely finds nothing here (proves the gap)
# ─────────────────────────────────────────────────────────────────────────────


def test_static_parser_finds_nothing_in_the_spa_shell():
    page = HTMLParser().parse(_PAGES["/"].replace("__OFFSCOPE__", "x").replace("__DEAD__", "y"), "http://x/")
    assert page.forms == []
    assert page.links == []


# ─────────────────────────────────────────────────────────────────────────────
# DomWatcher — real Chromium against the fixture SPA
# ─────────────────────────────────────────────────────────────────────────────


class TestDomWatcherCrawl:
    # Every fixture page links to /hang (see above), so every test in this
    # class pays Playwright's navigation timeout for it once — keep it short
    # throughout rather than only in the test that cares about the outcome.
    _TIMEOUT_MS = 2000

    def test_renders_js_and_discovers_forms_and_links(self, spa_server):
        result = DomWatcher(max_depth=2, nav_timeout_ms=self._TIMEOUT_MS).crawl(spa_server)

        urls = {ep.url.rstrip("/") for ep in result.endpoints}
        assert urls == {
            spa_server.rstrip("/"),
            spa_server.rstrip("/") + "/about",
            spa_server.rstrip("/") + "/page2",
            spa_server.rstrip("/") + "/page3",
        }

        seed_ep = next(ep for ep in result.endpoints if ep.url.rstrip("/") == spa_server.rstrip("/"))
        assert len(seed_ep.forms) == 1
        assert seed_ep.forms[0].fields[0].name == "q"
        assert seed_ep.status_code == 200

    def test_max_depth_stops_before_page4(self, spa_server):
        result = DomWatcher(max_depth=2, nav_timeout_ms=self._TIMEOUT_MS).crawl(spa_server)
        assert all(not ep.url.endswith("/page4") for ep in result.endpoints)

    def test_offscope_link_is_not_followed(self, spa_server):
        result = DomWatcher(max_depth=2, nav_timeout_ms=self._TIMEOUT_MS).crawl(spa_server)
        seed_host = spa_server.split("/")[2]
        assert all(seed_host in ep.url for ep in result.endpoints)

    def test_dead_link_is_recorded_as_failed_not_fatal(self, spa_server):
        result = DomWatcher(max_depth=2, nav_timeout_ms=self._TIMEOUT_MS).crawl(spa_server)
        assert len(result.failed_urls) >= 1
        assert any(url.endswith("/hang") for url in result.failed_urls)
        # The crawl still completed and found everything reachable.
        assert len(result.endpoints) == 4

    def test_respects_explicit_scope_guard(self, spa_server):
        """A scope guard that excludes everything yields just... nothing new."""
        guard = ScopeGuard(allowed_domains=["this-host-does-not-exist.invalid"])
        result = DomWatcher(max_depth=2).crawl(spa_server, scope_guard=guard)
        # Seed itself is always rendered once; its children are all filtered.
        assert len(result.endpoints) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Playwright not installed — degrades cleanly, never raises
# ─────────────────────────────────────────────────────────────────────────────


class TestPlaywrightAbsent:
    def test_missing_playwright_returns_empty_result(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
        monkeypatch.setitem(sys.modules, "playwright", None)
        result = DomWatcher().crawl("http://app.local/")
        assert result.endpoints == []
        assert result.seed_url == "http://app.local/"
