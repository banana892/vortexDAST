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
* BFS, same depth semantics as :class:`~core.crawler.Crawler`. ``max_workers``
  (default ``1``, matching the original single-page behaviour) controls how
  many pages render concurrently. Playwright's sync API ties a connection's
  browser/context/page to the thread that created them, so this isn't the
  static crawler's "share one pool, dispatch any URL to any worker" model —
  each worker thread owns its **own** full Playwright connection, browser and
  page for its whole lifetime, pulling ``(url, depth)`` pairs off one shared
  queue (``core.crawler._CrawlState`` for the lock-protected result/visited/
  cap bookkeeping, reused unchanged from the static crawler). Set
  ``max_workers`` above 1 only once a scan's dynamic-crawl phase is actually
  the bottleneck — each worker is a whole headless Chromium process.
* Also passively captures JSON ``fetch``/XHR calls the rendered page's own
  JS makes (``Content-Type: application/json``, ``POST``/``PUT``/``PATCH``)
  — the one piece of real API traffic the static crawler can never observe.
  Each distinct (method, URL) becomes its own synthetic
  :class:`~core.crawler.CrawledEndpoint` carrying the captured body in
  ``json_requests``, merged in by ``scanner.py`` the same way as any other
  dynamically-discovered endpoint. ``capture_json=False`` (or CLI
  ``--no-json-fuzz``) disables it.

Authenticated crawling
-----------------------
``crawl()`` accepts the scan's ``cookies`` (a ``requests`` cookie jar),
``extra_headers`` (e.g. an OAuth2 bearer token or an operator-supplied
``--header``) and ``http_credentials`` (HTTP Basic), so a form-login/OAuth2/
Basic-auth session carries into the rendered browser context instead of
every page rendering logged out. ``scanner.py`` passes these through from
the same authenticated ``Requester`` used for the static crawl.

A cookie with no explicit ``Domain`` attribute is "host-only": Python's
``http.cookiejar`` already stores it against whichever host actually issued
it (including mid-redirect, even across a login that hops hosts), not the
scan's seed URL — a cookie genuinely never carrying any host at all (e.g.
one supplied via the operator's own ``--cookie`` string, never seen in an
HTTP response) is the one real case left with nothing to attribute it to,
and falls back to the seed URL's host as the only sensible default.

Host-only cookies from a **dotless** hostname (``localhost``, a bare lab/
container hostname, ...) get a corrected domain too: ``http.cookiejar``
(RFC 2965's ``eff_request_host()``) appends a synthetic ``.local`` to any
such host's effective domain — a cookie from ``http://localhost/login``
ends up stored as ``cookie.domain == "localhost.local"``, which doesn't
match the page Playwright actually renders (``localhost``), so the browser
would otherwise never send it back. ``_to_playwright_cookies`` strips that
suffix for host-only cookies before handing them to
``BrowserContext.add_cookies()``.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from .crawler import (
    CapturedJsonRequest,
    CrawledEndpoint,
    Crawler,
    CrawlResult,
    ScopeGuard,
    _CrawlState,
)
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
        max_workers: int = 1,
    ) -> None:
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.nav_timeout_ms = nav_timeout_ms
        self.settle_ms = settle_ms
        self.parser = parser or HTMLParser()
        self.capture_json = capture_json
        self.max_captured_json = max_captured_json
        self.max_workers = max(1, max_workers)

    def crawl(
        self,
        seed_url: str,
        scope_guard: Optional[ScopeGuard] = None,
        cookies: Optional[Any] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        http_credentials: Optional[Dict[str, str]] = None,
    ) -> CrawlResult:
        """
        BFS-crawl ``seed_url`` with JavaScript rendered, same depth/scope
        semantics as :meth:`Crawler.crawl`. Never raises: a missing
        Playwright install, a browser that fails to launch, or any
        navigation error degrades to as much of a result as was gathered
        (possibly empty) with a logged warning — a scan must not fail just
        because the dynamic pass couldn't run.

        ``cookies`` (a ``requests`` cookie jar), ``extra_headers`` and
        ``http_credentials`` (``{"username": ..., "password": ...}`` for
        HTTP Basic) carry the scan's authenticated session into the browser
        context — see the module docstring's "Authenticated crawling".
        """
        result = CrawlResult(seed_url=seed_url)
        self._captured_json: List[CapturedJsonRequest] = []
        self._captured_json_keys: Set[Tuple[str, str]] = set()
        self._capture_lock = threading.Lock()

        try:
            import playwright.sync_api  # noqa: F401 — see docstring: each worker
            # imports sync_playwright itself, so this is only an availability probe.
        except ImportError:
            logger.warning(
                "playwright is not installed — dynamic crawl skipped. "
                "Install with: pip install playwright && playwright install chromium"
            )
            return result

        guard = scope_guard or ScopeGuard.from_seed(seed_url)
        seed = Crawler._normalise_url(seed_url)
        state = _CrawlState(result=result, visited={seed}, max_endpoints=self.max_pages)

        work_q: "queue.Queue[Optional[Tuple[str, int]]]" = queue.Queue()
        work_q.put((seed, 0))

        workers = [
            threading.Thread(
                target=self._worker_loop,
                args=(work_q, state, guard, seed_url, cookies, extra_headers, http_credentials),
                name=f"vdast-dom-watcher-{i}",
                daemon=True,
            )
            for i in range(self.max_workers)
        ]
        for w in workers:
            w.start()

        work_q.join()
        for _ in workers:
            work_q.put(None)
        for w in workers:
            w.join()

        if self._captured_json:
            # Each captured call becomes its own synthetic endpoint (no
            # forms/links, just the one JSON request) so every downstream
            # module can fuzz it via CrawledEndpoint.json_requests exactly
            # like it already fuzzes endpoint.forms — no new module hook.
            #
            # Keyed by (method, url), not url alone: a page can be rendered
            # (GET, via navigation) at the exact same URL an on-page fetch()
            # POSTs/PUTs/PATCHes to — e.g. a REST resource that's also a
            # browsable page — and that capture must not be dropped just
            # because something else already exists at that URL string.
            # _on_request's own (method, url) dedup already guarantees no
            # two entries in self._captured_json collide, so this is only
            # ever checked against *other already-added* JSON endpoints —
            # kept explicit so that invariant stays enforced even if the
            # capture path changes later.
            existing_method_urls = {
                (ep.json_requests[0].method, ep.url) for ep in result.endpoints if ep.json_requests
            }
            added = 0
            for captured in self._captured_json:
                key = (captured.method, captured.url)
                if key in existing_method_urls:
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
                existing_method_urls.add(key)
                added += 1
            if added:
                logger.info("  + %d JSON API endpoint(s) captured from page JS", added)

        logger.info(
            "Dynamic crawl complete | seed=%s | endpoints=%d | failed=%d",
            seed_url, len(result.endpoints), len(result.failed_urls),
        )
        return result

    @staticmethod
    def _to_playwright_cookies(cookies: Any, seed_url: str) -> List[Dict[str, Any]]:
        """
        Convert a ``requests`` cookie jar into the list-of-dicts shape
        Playwright's ``BrowserContext.add_cookies()`` expects.
        """
        fallback_domain = urlsplit(seed_url).hostname or ""
        out: List[Dict[str, Any]] = []
        for cookie in cookies:
            domain = getattr(cookie, "domain", "") or fallback_domain
            # Python's http.cookiejar (RFC 2965 eff_request_host()) appends a
            # synthetic ".local" to any host-only cookie's domain when the
            # issuing host has no dot in it — e.g. a cookie from
            # "http://localhost/login" ends up with cookie.domain ==
            # "localhost.local". That doesn't match the page Playwright
            # actually renders ("localhost"), so the cookie silently never
            # gets sent. domain_specified=False means this IS that synthetic
            # value (never a server's own explicit Domain=...), so it's safe
            # to undo. Affects any dotless hostname: "localhost", a bare lab/
            # container hostname, etc. — not real domains or IP addresses.
            if not getattr(cookie, "domain_specified", True) and domain.endswith(".local"):
                domain = domain[: -len(".local")]
            if not domain or not getattr(cookie, "name", None):
                continue
            out.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": domain,
                "path": getattr(cookie, "path", "/") or "/",
                "secure": bool(getattr(cookie, "secure", False)),
            })
        return out

    def _on_request(self, request: Any) -> None:
        """
        Record a same-page JSON ``fetch``/XHR call. Never raises: a
        malformed or unreadable request is simply skipped, since this runs
        on Playwright's event thread and an exception here must not be able
        to take the browser down mid-crawl. With ``max_workers`` > 1, each
        worker's own page fires this concurrently, so every access to the
        shared capture state goes through ``self._capture_lock``.
        """
        with self._capture_lock:
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
        with self._capture_lock:
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
        self, page: Any, url: str, depth: int, state: _CrawlState
    ) -> List[Tuple[str, int]]:
        """
        Navigate to ``url``, record a CrawledEndpoint, return in-depth child
        URLs. ``page`` is this worker thread's own — never touched by another
        thread — so only the final write into the shared ``state`` needs its
        lock.
        """
        try:
            response = page.goto(url, wait_until="networkidle")
        except Exception as exc:  # noqa: BLE001 — timeouts/nav errors are per-page, not fatal
            logger.debug("Dynamic navigation failed for %s: %s", url, exc)
            with state._lock:
                state.result.failed_urls[url] = str(exc)
            return []

        page.wait_for_timeout(self.settle_ms)

        try:
            html = page.content()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not read rendered DOM for %s: %s", url, exc)
            with state._lock:
                state.result.failed_urls[url] = str(exc)
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
        with state._lock:
            state.result.endpoints.append(endpoint)
        logger.info(
            "  ✓ [dynamic] %s [HTTP %d] | forms=%d links=%d",
            url, status_code, len(parsed.forms), len(parsed.links),
        )

        child_depth = depth + 1
        return [
            (Crawler._normalise_url(link.url), child_depth)
            for link in parsed.links
        ]

    def _worker_loop(
        self,
        work_q: "queue.Queue[Optional[Tuple[str, int]]]",
        state: _CrawlState,
        guard: ScopeGuard,
        seed_url: str,
        cookies: Optional[Any],
        extra_headers: Optional[Dict[str, str]],
        http_credentials: Optional[Dict[str, str]],
    ) -> None:
        """
        One worker's full lifecycle: its own Playwright connection, browser,
        context and page — Playwright's sync API ties a connection's
        resources to the thread that created them, so nothing here can be
        shared with another worker — pulling ``(url, depth)`` pairs off the
        shared queue until the ``None`` sentinel. Never raises: a browser that
        fails to launch (or crashes outright) falls back to draining this
        worker's share of the queue as failed rather than hanging the other
        workers' ``work_q.join()`` forever.
        """
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright

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
                    self._drain(work_q, state, guard, page=None)
                    return
                try:
                    context_kwargs: Dict[str, Any] = {}
                    if extra_headers:
                        context_kwargs["extra_http_headers"] = dict(extra_headers)
                    if http_credentials:
                        context_kwargs["http_credentials"] = http_credentials
                    context = browser.new_context(**context_kwargs)
                    if cookies:
                        pw_cookies = self._to_playwright_cookies(cookies, seed_url)
                        if pw_cookies:
                            context.add_cookies(pw_cookies)  # type: ignore[arg-type]

                    page = context.new_page()
                    page.set_default_navigation_timeout(self.nav_timeout_ms)
                    if self.capture_json:
                        page.on("request", self._on_request)

                    self._drain(work_q, state, guard, page)
                finally:
                    browser.close()
        except Exception as exc:  # noqa: BLE001 — see docstring
            logger.error("Dynamic crawl worker aborted: %s", exc)
            self._drain(work_q, state, guard, page=None)

    def _drain(
        self,
        work_q: "queue.Queue[Optional[Tuple[str, int]]]",
        state: _CrawlState,
        guard: ScopeGuard,
        page: Any,
    ) -> None:
        """
        Pull ``(url, depth)`` pairs off ``work_q`` until the ``None``
        sentinel, enqueueing in-scope children as they're discovered. With
        ``page=None`` (this worker never got a browser), every item is
        recorded as failed instead of rendered — the item still gets
        ``task_done()``'d either way, so ``work_q.join()`` always completes
        even if every worker's browser launch fails.
        """
        while True:
            item = work_q.get()
            try:
                if item is None:
                    return
                url, depth = item
                with state._lock:
                    if state.cap_reached():
                        continue
                if page is None:
                    with state._lock:
                        state.result.failed_urls[url] = "no browser available in this worker"
                    continue
                children = self._render_one(page, url, depth, state)
                for child_url, child_depth in children:
                    with state._lock:
                        if child_depth > self.max_depth or child_url in state.visited:
                            continue
                        if not guard.is_in_scope(child_url):
                            continue
                        if state.cap_reached():
                            continue
                        state.visited.add(child_url)
                    work_q.put((child_url, child_depth))
            finally:
                work_q.task_done()
