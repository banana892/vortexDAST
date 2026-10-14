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
    # Issues a JSON fetch() POST on load — the real API traffic a static
    # crawler can never observe, since it never runs this script at all.
    "/jsonapi": """<!DOCTYPE html><html><body><script>
        fetch('/api/widgets', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name: 'gadget', qty: 3})
        }).catch(() => {});
        </script></body></html>""",
    # A page that's *also* a REST resource: rendered via GET navigation
    # (its own CrawledEndpoint) AND fetch()-POSTed to that exact same URL
    # (a captured JSON endpoint) — the dedup-by-URL-alone bug would drop
    # the latter because the former already "claims" that URL string.
    "/samepath": """<!DOCTYPE html><html><body><script>
        fetch('/samepath', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'ping'})
        }).catch(() => {});
        </script></body></html>""",
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
            if path == "/whoami":
                # Echoes the request's own Cookie/Authorization headers into
                # a link, so a test can prove what the *browser* actually
                # sent without needing a session store on this fake server.
                from urllib.parse import quote

                cookie = quote(self.headers.get("Cookie", "none"))
                auth = quote(self.headers.get("Authorization", "none"))
                body = (
                    f'<!DOCTYPE html><html><body>'
                    f'<a href="/confirmed?cookie={cookie}&auth={auth}">go</a>'
                    f"</body></html>"
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body.encode())
                return
            if path == "/basic":
                # Real HTTP Basic: challenge first, same as a real server —
                # Playwright's http_credentials only responds once challenged.
                from urllib.parse import quote

                auth = self.headers.get("Authorization")
                if not auth:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="test"')
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = (
                    f'<!DOCTYPE html><html><body>'
                    f'<a href="/confirmed?auth={quote(auth)}">go</a>'
                    f"</body></html>"
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body.encode())
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
# Authenticated crawling — cookies/headers/HTTP-Basic carried into the
# browser context (IMPROVEMENTS.md's DomWatcher cookie-jar follow-up)
# ─────────────────────────────────────────────────────────────────────────────


class TestDomWatcherAuthenticatedContext:
    _TIMEOUT_MS = 2000

    def test_cookies_and_headers_reach_the_browser(self, spa_server):
        from urllib.parse import urlsplit

        import requests

        jar = requests.cookies.RequestsCookieJar()
        jar.set("session", "secret123", domain=urlsplit(spa_server).hostname, path="/")

        result = DomWatcher(max_depth=0, nav_timeout_ms=self._TIMEOUT_MS).crawl(
            spa_server + "whoami",
            cookies=jar,
            extra_headers={"Authorization": "Bearer tok-abc"},
        )
        endpoint = next(ep for ep in result.endpoints if ep.url.endswith("/whoami"))
        assert len(endpoint.links) == 1
        confirmed_url = endpoint.links[0].url
        assert "session%3Dsecret123" in confirmed_url
        assert "Bearer%20tok-abc" in confirmed_url

    def test_without_cookies_or_headers_server_sees_none(self, spa_server):
        result = DomWatcher(max_depth=0, nav_timeout_ms=self._TIMEOUT_MS).crawl(
            spa_server + "whoami"
        )
        endpoint = next(ep for ep in result.endpoints if ep.url.endswith("/whoami"))
        confirmed_url = endpoint.links[0].url
        assert "cookie=none" in confirmed_url
        assert "auth=none" in confirmed_url

    def test_http_credentials_are_sent_as_basic_auth(self, spa_server):
        result = DomWatcher(max_depth=0, nav_timeout_ms=self._TIMEOUT_MS).crawl(
            spa_server + "basic",
            http_credentials={"username": "alice", "password": "wonderland"},
        )
        endpoint = next(ep for ep in result.endpoints if ep.url.endswith("/basic"))
        confirmed_url = endpoint.links[0].url
        # "alice:wonderland" base64-encoded, URL-quoted by the fixture server.
        import base64
        from urllib.parse import quote

        expected = quote(f"Basic {base64.b64encode(b'alice:wonderland').decode()}")
        assert expected in confirmed_url


# ─────────────────────────────────────────────────────────────────────────────
# Dotless-hostname cookie domain ("localhost.local" cookiejar quirk)
# ─────────────────────────────────────────────────────────────────────────────


def _host_only_cookie(name: str, value: str, domain: str):
    """A ``http.cookiejar.Cookie`` shaped exactly like one http.cookiejar
    itself would store for a host-only (no explicit ``Domain=``) Set-Cookie —
    ``domain_specified=False`` is the signal ``_to_playwright_cookies`` keys
    on, which ``requests.cookies.RequestsCookieJar.set()`` can't produce
    directly (it always sets ``domain_specified=True`` when given a domain).
    """
    import http.cookiejar

    return http.cookiejar.Cookie(
        version=0, name=name, value=value,
        port=None, port_specified=False,
        domain=domain, domain_specified=False, domain_initial_dot=False,
        path="/", path_specified=True,
        secure=False, expires=None, discard=True,
        comment=None, comment_url=None, rest={},
    )


class TestDomWatcherDotlessHostCookie:
    def test_to_playwright_cookies_strips_synthetic_local_suffix(self):
        cookie = _host_only_cookie("SID", "abc", "localhost.local")
        out = DomWatcher._to_playwright_cookies([cookie], "http://localhost:8080/")
        assert out == [
            {"name": "SID", "value": "abc", "domain": "localhost", "path": "/", "secure": False}
        ]

    def test_to_playwright_cookies_leaves_explicit_domain_alone(self):
        import http.cookiejar

        cookie = http.cookiejar.Cookie(
            version=0, name="SID", value="abc", port=None, port_specified=False,
            domain=".example.local", domain_specified=True, domain_initial_dot=True,
            path="/", path_specified=True, secure=False, expires=None, discard=True,
            comment=None, comment_url=None, rest={},
        )
        out = DomWatcher._to_playwright_cookies([cookie], "http://example.local/")
        # A server that explicitly asked for ".example.local" is trusted as-is
        # — only the *synthetic*, host-only case gets corrected.
        assert out[0]["domain"] == ".example.local"

    def test_to_playwright_cookies_leaves_real_domains_alone(self):
        cookie = _host_only_cookie("SID", "abc", "app.example.com")
        out = DomWatcher._to_playwright_cookies([cookie], "http://app.example.com/")
        assert out[0]["domain"] == "app.example.com"

    def test_dotless_host_cookie_reaches_the_browser(self):
        """
        End-to-end regression test for the bug itself: a real login response
        against a dotless host ("localhost") issues a host-only cookie that
        http.cookiejar stores as "localhost.local" — reproduced here via an
        actual HTTP round-trip, not a constructed Cookie, since that's the
        only way to get requests' real cookiejar behaviour. Before the fix,
        this cookie would silently never reach the rendered page.
        """
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from urllib.parse import quote

        import requests

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                cookie = quote(self.headers.get("Cookie", "none"))
                body = (
                    f'<html><body><a href="/confirmed?cookie={cookie}">go</a>'
                    "</body></html>"
                ).encode()
                self.send_response(200)
                self.send_header("Set-Cookie", "SID=abc; Path=/")
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            seed = f"http://localhost:{server.server_port}/"

            session = requests.Session()
            session.get(seed)
            issued = next(iter(session.cookies))
            assert issued.domain == "localhost.local"  # the quirk this test guards against

            result = DomWatcher(max_depth=0, nav_timeout_ms=3000).crawl(
                seed, cookies=session.cookies
            )
            endpoint = result.endpoints[0]
            assert len(endpoint.links) == 1
            assert "SID%3Dabc" in endpoint.links[0].url
        finally:
            server.shutdown()


# ─────────────────────────────────────────────────────────────────────────────
# JSON API capture — passive fetch()/XHR observation (Phase D, scoped in
# IMPROVEMENTS.md's "API testing" entry)
# ─────────────────────────────────────────────────────────────────────────────


class TestDomWatcherJsonCapture:
    _TIMEOUT_MS = 2000

    def test_captures_json_fetch_as_synthetic_endpoint(self, spa_server):
        result = DomWatcher(max_depth=0, nav_timeout_ms=self._TIMEOUT_MS).crawl(
            spa_server + "jsonapi"
        )
        api_endpoints = [ep for ep in result.endpoints if ep.url.endswith("/api/widgets")]
        assert len(api_endpoints) == 1

        endpoint = api_endpoints[0]
        assert len(endpoint.json_requests) == 1
        captured = endpoint.json_requests[0]
        assert captured.method == "POST"
        assert captured.body == {"name": "gadget", "qty": 3}

        # The page itself still gets its own (JSON-free) endpoint as usual.
        page_endpoint = next(ep for ep in result.endpoints if ep.url.endswith("/jsonapi"))
        assert page_endpoint.json_requests == []

    def test_capture_json_false_disables_it(self, spa_server):
        result = DomWatcher(
            max_depth=0, nav_timeout_ms=self._TIMEOUT_MS, capture_json=False
        ).crawl(spa_server + "jsonapi")
        assert all(ep.json_requests == [] for ep in result.endpoints)
        assert not any(ep.url.endswith("/api/widgets") for ep in result.endpoints)

    def test_captured_json_not_dropped_by_same_url_page(self, spa_server):
        """
        A fetch() POST to the exact same URL the page itself was rendered
        at must not be silently dropped just because that URL string
        already "belongs" to the rendered-page endpoint — regression test
        for dedup keyed on URL alone instead of (method, url).
        """
        result = DomWatcher(max_depth=0, nav_timeout_ms=self._TIMEOUT_MS).crawl(
            spa_server + "samepath"
        )
        matching = [ep for ep in result.endpoints if ep.url.endswith("/samepath")]
        assert len(matching) == 2

        page_endpoint = next(ep for ep in matching if not ep.json_requests)
        json_endpoint = next(ep for ep in matching if ep.json_requests)
        assert page_endpoint is not json_endpoint

        captured = json_endpoint.json_requests[0]
        assert captured.method == "POST"
        assert captured.body == {"action": "ping"}


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


# ─────────────────────────────────────────────────────────────────────────────
# max_workers — concurrent dynamic crawling (each worker owns its own
# Playwright connection/browser/page; see core/dom_watcher.py's docstring)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def slow_spa_server():
    """
    A seed page linking to four pages that each take ~1s to respond
    server-side — long enough that rendering them concurrently vs.
    sequentially produces a clearly measurable wall-clock difference, not a
    noise-level one.
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    n_slow = 4
    delay_s = 1.0
    seed_body = "<html><body>" + "".join(
        f'<a href="/slow{i}">slow{i}</a>' for i in range(n_slow)
    ) + "</body></html>"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.rstrip("/") or "/"
            if path.startswith("/slow"):
                time.sleep(delay_s)
                body = "<html><body>done</body></html>"
            else:
                body = seed_body
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()


class TestDomWatcherConcurrency:
    def test_max_workers_discovers_same_endpoints_as_sequential(self, spa_server):
        sequential = DomWatcher(max_depth=2, nav_timeout_ms=2000, max_workers=1).crawl(spa_server)
        concurrent = DomWatcher(max_depth=2, nav_timeout_ms=2000, max_workers=4).crawl(spa_server)
        assert {ep.url for ep in concurrent.endpoints} == {ep.url for ep in sequential.endpoints}
        assert set(concurrent.failed_urls) == set(sequential.failed_urls)

    def test_max_workers_renders_pages_concurrently(self, slow_spa_server):
        start = time.monotonic()
        sequential = DomWatcher(max_depth=1, nav_timeout_ms=5000, max_workers=1).crawl(
            slow_spa_server
        )
        sequential_elapsed = time.monotonic() - start
        assert len(sequential.endpoints) == 5  # seed + 4 slow pages

        start = time.monotonic()
        concurrent = DomWatcher(max_depth=1, nav_timeout_ms=5000, max_workers=4).crawl(
            slow_spa_server
        )
        concurrent_elapsed = time.monotonic() - start
        assert len(concurrent.endpoints) == 5

        # Four ~1s pages: sequential pays all four in series, concurrent pays
        # them in parallel — a generous margin to stay robust under CI load
        # while still proving real concurrency, not a noise-level gain.
        assert concurrent_elapsed < sequential_elapsed * 0.65

    def test_every_worker_failing_to_launch_does_not_hang(self, spa_server, monkeypatch):
        from playwright.sync_api import Error as PlaywrightError

        def _always_fail(self, **kwargs):
            raise PlaywrightError("simulated launch failure")

        monkeypatch.setattr("playwright.sync_api.BrowserType.launch", _always_fail)

        outcome: dict = {}

        def _run():
            outcome["result"] = DomWatcher(max_depth=1, max_workers=3).crawl(spa_server)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=15)
        assert not t.is_alive(), "crawl() hung instead of draining as failed"

        result = outcome["result"]
        assert result.endpoints == []
        assert spa_server.rstrip("/") in result.failed_urls
