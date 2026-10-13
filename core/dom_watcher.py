"""
VortexDAST – core/dom_watcher.py
────────────────────────────────────────────────────────────────────────────
Dynamic (JS-rendered) crawling via a headless Playwright browser.

Why this exists
----------------
``core/crawler.py`` only ever sees the raw HTTP response body. A modern SPA's
initial HTML is often an empty shell (``<div id="root"></div>``) with every
link, form and piece of content injected by JavaScript after load. Against
such a target the static crawler legitimately finds nothing — not because
there's nothing there, but because it never ran the client-side code that
builds the page.

:class:`DomWatcher` renders each page in headless Chromium, waits for the
network to settle, then hands the *fully rendered* DOM's HTML to the exact
same :class:`~core.parser.HTMLParser` the static crawler uses — so every
downstream module, dedup rule and report field behaves identically to an
ordinary :class:`~core.crawler.CrawledEndpoint`; the only difference is where
the HTML came from.

Design
------
* Reuses ``ScopeGuard``/``HTMLParser``/``CrawledEndpoint``/``CrawlResult`` —
  no parallel data model.
* Meant to be *composed* with the static crawl (see ``crawler.py``'s module
  docstring): run after it, keep everything the static pass already found,
  and merge in only the endpoints the static pass could never have seen
  (scanner.py does this merge).
* One browser, one page, navigated sequentially (BFS, same depth semantics
  as :class:`~core.crawler.Crawler`).
* Also passively captures JSON ``fetch``/XHR calls the rendered page's own
  JS makes (``Content-Type: application/json``, ``POST``/``PUT``/``PATCH``)
  — the one piece of real API traffic the static crawler can never observe.
  Each distinct (method, URL) becomes its own synthetic
  :class:`~core.crawler.CrawledEndpoint` carrying the captured body in
  ``json_requests``, merged in by ``scanner.py`` the same way as any other
  dynamically-discovered endpoint. ``capture_json=False`` (or CLI
  ``--no-json-fuzz``) disables it.

shortcut: single page, no concurrency — Playwright's sync API isn't
thread-safe the way the static crawler's worker pool needs, and JS
rendering is the expensive, blocking step regardless; upgrade to multiple
browser contexts if dynamic crawls of large sites become a bottleneck.

shortcut: unauthenticated only — this does not carry over the scan's cookie
jar/auth headers into the browser context. Combining dynamic rendering with
an authenticated session is its own Phase D follow-up (IMPROVEMENTS.md §4),
not done here.
"""

from __future__ import annotations

import json
import logging
from typing import Any, List, Optional, Set, Tuple

from .crawler import CapturedJsonRequest, CrawledEndpoint, CrawlResult, Crawler, ScopeGuard
from .parser import HTMLParser, ParsedPage

logger = logging.getLogger(__name__)

#: Hard ceiling so a pathological SPA can't turn a dynamic crawl into an
#: unbounded browser-driven session.
DEFAULT_MAX_PAGES = 40
#: Per-page navigation timeout.
DEFAULT_NAV_TIMEOUT_MS = 20_000
#: Extra wait after "networkidle" for client-side rendering that keeps
#: mutating the DOM after its last network request (e.g. a render tied to a
#: timer or an animation frame rather than a fetch).
DEFAULT_SETTLE_MS = 1_500
#: Hard cap on distinct (method, URL) JSON requests captured per crawl —
#: bounds synthetic-endpoint growth against a chatty SPA that polls the same
#: API repeatedly.
DEFAULT_MAX_CAPTURED_JSON = 40


class DomWatcher:
    """Headless-browser BFS crawl that renders JavaScript before extracting the DOM."""

    def __init__(
        self,
        max_depth: int = 3,
        max_pages: int = DEFAULT_MAX_PAGES,
        nav_timeout_ms: int = DEFAULT_NAV_TIMEOUT_MS,
        settle_ms: int = DEFAULT_SETTLE_MS,
        parser: Optional[HTMLParser] = None,
        capture_json: bool = True,
        max_captured_json: int = DEFAULT_MAX_CAPTURED_JSON,
    ) -> None:
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.nav_timeout_ms = nav_timeout_ms
        self.settle_ms = settle_ms
        self.parser = parser or HTMLParser()
        self.capture_json = capture_json
        self.max_captured_json = max_captured_json

    def crawl(self, seed_url: str, scope_guard: Optional[ScopeGuard] = None) -> CrawlResult:
        """
        BFS-crawl ``seed_url`` with JavaScript rendered, same depth/scope
        semantics as :meth:`Crawler.crawl`. Never raises: a missing
        Playwright install, a browser that fails to launch, or any
        navigation error degrades to as much of a result as was gathered
        (possibly empty) with a logged warning — a scan must not fail just
        because the dynamic pass couldn't run.
        """
        result = CrawlResult(seed_url=seed_url)
        self._captured_json: List[CapturedJsonRequest] = []
        self._captured_json_keys: Set[Tuple[str, str]] = set()

        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright
        except ImportError:
            logger.warning(
                "playwright is not installed — dynamic crawl skipped. "
                "Install with: pip install playwright && playwright install chromium"
            )
            return result

        guard = scope_guard or ScopeGuard.from_seed(seed_url)
        seed = Crawler._normalise_url(seed_url)
        visited = {seed}
        frontier: List[Tuple[str, int]] = [(seed, 0)]

        try:
            with sync_playwright() as pw:
                try:
                    browser = pw.chromium.launch(headless=True)
                except PlaywrightError as exc:
                    logger.warning(
                        "Could not launch headless Chromium (%s) — is it installed? "
                        "Run: playwright install chromium",
                        exc,
                    )
                    return result

                try:
                    page = browser.new_page()
                    page.set_default_navigation_timeout(self.nav_timeout_ms)
                    if self.capture_json:
                        page.on("request", self._on_request)

                    while frontier and len(result.endpoints) < self.max_pages:
                        url, depth = frontier.pop(0)
                        children = self._render_one(page, url, depth, result)
                        for child_url, child_depth in children:
                            if child_depth > self.max_depth or child_url in visited:
                                continue
                            if not guard.is_in_scope(child_url):
                                continue
                            visited.add(child_url)
                            frontier.append((child_url, child_depth))
                finally:
                    browser.close()
        except Exception as exc:  # noqa: BLE001 — a crashed browser must not sink the scan
            logger.error("Dynamic crawl aborted: %s", exc)

        if self._captured_json:
            # Each captured call becomes its own synthetic endpoint (no
            # forms/links, just the one JSON request) so every downstream
            # module can fuzz it via CrawledEndpoint.json_requests exactly
            # like it already fuzzes endpoint.forms — no new module hook.
            #
            # shortcut: dedup/merge is by URL alone, so two captures to the
            # same URL with different HTTP methods collapse into one
            # synthetic endpoint; upgrade to (method, url) if that turns out
            # to matter in practice.
            existing_urls = result.all_urls
            added = 0
            for captured in self._captured_json:
                if captured.url in existing_urls:
                    continue
                result.endpoints.append(
                    CrawledEndpoint(
                        url=captured.url,
                        status_code=0,
                        depth=0,
                        query_params=HTMLParser.extract_query_params(captured.url),
                        json_requests=[captured],
                    )
                )
                existing_urls.add(captured.url)
                added += 1
            if added:
                logger.info("  + %d JSON API endpoint(s) captured from page JS", added)

        logger.info(
            "Dynamic crawl complete | seed=%s | endpoints=%d | failed=%d",
            seed_url, len(result.endpoints), len(result.failed_urls),
        )
        return result

    def _on_request(self, request: Any) -> None:
        """
        Record a same-page JSON ``fetch``/XHR call. Never raises: a
        malformed or unreadable request is simply skipped, since this runs
        on Playwright's event thread and an exception here must not be able
        to take the browser down mid-crawl.
        """
        if len(self._captured_json) >= self.max_captured_json:
            return
        try:
            method = request.method
            if method not in ("POST", "PUT", "PATCH"):
                return
            content_type = request.headers.get("content-type", "")
            if "application/json" not in content_type.lower():
                return
            post_data = request.post_data
            if not post_data:
                return
            body = json.loads(post_data)
        except Exception:  # noqa: BLE001 — see docstring
            return

        key = (method, request.url)
        if key in self._captured_json_keys:
            return
        self._captured_json_keys.add(key)
        self._captured_json.append(
            CapturedJsonRequest(
                url=request.url, method=method, body=body, headers=dict(request.headers)
            )
        )

    # ── Internal ─────────────────────────────────────────────────────────

    def _render_one(
        self, page: Any, url: str, depth: int, result: CrawlResult
    ) -> List[Tuple[str, int]]:
        """Navigate to ``url``, record a CrawledEndpoint, return in-depth child URLs."""
        try:
            response = page.goto(url, wait_until="networkidle")
        except Exception as exc:  # noqa: BLE001 — timeouts/nav errors are per-page, not fatal
            logger.debug("Dynamic navigation failed for %s: %s", url, exc)
            result.failed_urls[url] = str(exc)
            return []

        page.wait_for_timeout(self.settle_ms)

        try:
            html = page.content()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not read rendered DOM for %s: %s", url, exc)
            result.failed_urls[url] = str(exc)
            return []

        try:
            parsed: ParsedPage = self.parser.parse(html, url)
        except Exception as exc:
            logger.error("Dynamic parse error at %s: %s", url, exc)
            return []

        status_code = response.status if response is not None else 0
        headers = dict(response.headers) if response is not None else {}

        endpoint = CrawledEndpoint(
            url=url,
            status_code=status_code,
            depth=depth,
            forms=parsed.forms,
            links=parsed.links,
            query_params=HTMLParser.extract_query_params(url),
            response_headers=headers,
        )
        result.endpoints.append(endpoint)
        logger.info(
            "  ✓ [dynamic] %s [HTTP %d] | forms=%d links=%d",
            url, status_code, len(parsed.forms), len(parsed.links),
        )

        child_depth = depth + 1
        return [
            (Crawler._normalise_url(link.url), child_depth)
            for link in parsed.links
        ]
