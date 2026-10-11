"""
VortexDAST – core/crawler.py
────────────────────────────────────────────────────────────────────────────
Concurrent BFS (Breadth-First Search) web crawler.

Responsibilities:
  • Accept a seed URL and discover all reachable endpoints within the
    configured scope (allowed domains, allowed/excluded paths, excluded file
    extensions).
  • Use the Requester for HTTP and the HTMLParser for link/form extraction.
  • Enforce a configurable maximum crawl depth and optional endpoint cap.
  • Fetch all URLs at the **same BFS depth level** concurrently using a
    ``concurrent.futures.ThreadPoolExecutor``, then advance to the next depth.
    This preserves correct BFS depth semantics while achieving intra-depth
    parallelism proportional to ``max_workers``.
  • Maintain thread-safe shared state (visited set, endpoint list, failed-URL
    map, running count) via a single ``threading.Lock``.
  • Collect and deduplicate every discovered URL, form, and query parameter
    set into a structured :class:`CrawlResult`.
  • Respect the scope rules defined in ``config.yaml`` so we never wander
    outside the target application.

Concurrency model
-----------------
All mutable crawler state that is accessed from worker threads is protected
by ``_CrawlState._lock``:

* ``visited``          – URL deduplication set (read + write under lock)
* ``result.endpoints`` – list append under lock
* ``result.failed_urls`` – dict write under lock
* ``endpoint_count``   – monotonic counter checked against ``max_endpoints``

Worker threads are pure functions (:func:`_fetch_and_parse`) that receive the
lock and state container as arguments; they never mutate ``Crawler`` instance
attributes.

This module implements *static* crawling only (plain HTTP + BeautifulSoup).
Dynamic JS-rendered crawling via Playwright lives in ``core/dom_watcher.py``
(Phase 3) and can be composed with this crawler.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .parser import HTMLParser, ParsedPage
from .requester import Requester

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class CrawledEndpoint:
    """
    A fully characterised endpoint discovered during crawling.

    This is the primary data unit fed into scanning modules.  It bundles the
    URL together with every attack surface element extracted from that page so
    that fuzzers don't need to re-fetch or re-parse.
    """

    url: str
    """Absolute URL of the endpoint."""

    status_code: int
    """HTTP status code returned when the page was fetched."""

    depth: int
    """BFS depth at which this endpoint was discovered (0 = seed URL)."""

    forms: List = field(default_factory=list)
    """All HTML forms found on this page."""

    links: List = field(default_factory=list)
    """All hyperlinks found on this page."""

    query_params: Dict[str, List[str]] = field(default_factory=dict)
    """Query parameters present in this endpoint's own URL."""

    response_headers: Dict[str, str] = field(default_factory=dict)
    """HTTP response headers — used by the headers auditor module."""


@dataclass
class CrawlResult:
    """
    Aggregate output of a complete crawl run.

    Holds the full list of crawled endpoints plus convenience sets for quick
    membership checks.  Scanning modules iterate over ``endpoints`` directly.
    """

    seed_url: str
    """The URL from which crawling started."""

    endpoints: List[CrawledEndpoint] = field(default_factory=list)
    """All successfully fetched endpoints, including their attack surface data."""

    failed_urls: Dict[str, str] = field(default_factory=dict)
    """
    URLs that could not be fetched mapped to the error message.
    Useful for reporting connectivity issues.
    """

    @property
    def all_urls(self) -> Set[str]:
        """Set of all endpoint URLs for quick membership checks."""
        return {ep.url for ep in self.endpoints}

    @property
    def total_forms(self) -> int:
        """Total number of forms discovered across all endpoints."""
        return sum(len(ep.forms) for ep in self.endpoints)

    @property
    def total_links(self) -> int:
        """Total number of unique links discovered."""
        return sum(len(ep.links) for ep in self.endpoints)

    def summary(self) -> str:
        """Human-readable one-liner for logging / CLI output."""
        return (
            f"Crawl complete | seed={self.seed_url} | "
            f"endpoints={len(self.endpoints)} | "
            f"forms={self.total_forms} | "
            f"failed={len(self.failed_urls)}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Internal thread-safe state container
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class _CrawlState:
    """
    Mutable BFS state shared across all worker threads.

    All fields must be read or written while holding ``_lock``.

    Parameters
    ----------
    result : CrawlResult
        The accumulator for discovered endpoints and failures.
    visited : set[str]
        URLs already enqueued or fetched — prevents re-fetching.
    max_endpoints : int | None
        Hard cap on ``len(result.endpoints)``.  ``None`` = unlimited.
    """

    result: CrawlResult
    visited: Set[str]
    max_endpoints: Optional[int]
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def endpoint_count(self) -> int:
        """Current number of successfully fetched endpoints (call under lock)."""
        return len(self.result.endpoints)

    def cap_reached(self) -> bool:
        """Return ``True`` if ``max_endpoints`` is set and has been reached."""
        return (
            self.max_endpoints is not None
            and self.endpoint_count >= self.max_endpoints
        )


# ─────────────────────────────────────────────────────────────────────────────
# Scope guard helper
# ─────────────────────────────────────────────────────────────────────────────


class ScopeGuard:
    """
    Determines whether a given URL falls within the configured scan scope.

    Rules (checked in order):
      1. Scheme must be ``http`` or ``https``.
      2. Netloc must be in ``allowed_domains``.
      3. Path must not start with any ``excluded_paths`` prefix.
      4. Path extension must not be in ``excluded_extensions``.
      5. If ``allowed_paths`` is non-empty, the path must start with one.
    """

    def __init__(
        self,
        allowed_domains: List[str],
        allowed_paths: Optional[List[str]] = None,
        excluded_paths: Optional[List[str]] = None,
        excluded_extensions: Optional[List[str]] = None,
    ) -> None:
        self.allowed_domains: Set[str] = set(allowed_domains)
        self.allowed_paths: List[str] = allowed_paths or []
        self.excluded_paths: List[str] = excluded_paths or []
        self.excluded_extensions: Set[str] = set(excluded_extensions or [])

    def is_in_scope(self, url: str) -> bool:
        """Return ``True`` if ``url`` should be crawled/tested."""
        try:
            parsed = urlparse(url)
        except Exception:
            return False

        # ── Scheme check ─────────────────────────────────────────────────────
        if parsed.scheme not in {"http", "https"}:
            return False

        # ── Domain check ─────────────────────────────────────────────────────
        netloc = parsed.netloc.lower()
        if netloc not in self.allowed_domains:
            return False

        path = parsed.path.lower()

        # ── Excluded path prefixes ────────────────────────────────────────────
        for excluded in self.excluded_paths:
            if path.startswith(excluded.lower()):
                logger.debug("Skipping excluded path: %s", url)
                return False

        # ── Excluded file extensions ──────────────────────────────────────────
        # Check the last segment of the path for a file extension.
        last_segment = path.rsplit("/", 1)[-1]
        if "." in last_segment:
            ext = "." + last_segment.rsplit(".", 1)[-1]
            if ext in self.excluded_extensions:
                logger.debug("Skipping excluded extension %s: %s", ext, url)
                return False

        # ── Allowed path prefixes (whitelist) ────────────────────────────────
        if self.allowed_paths:
            if not any(path.startswith(ap.lower()) for ap in self.allowed_paths):
                logger.debug("URL outside allowed_paths, skipping: %s", url)
                return False

        return True

    @classmethod
    def from_seed(
        cls,
        seed_url: str,
        config_scope: Optional[dict] = None,
    ) -> "ScopeGuard":
        """
        Construct a :class:`ScopeGuard` from the crawler config section.

        If ``config_scope[\"allowed_domains\"]`` is empty, the seed URL's netloc
        is used automatically so that the crawler stays on-target by default.

        Parameters
        ----------
        seed_url : str
            The initial URL passed to the crawler.
        config_scope : dict | None
            The ``scope`` section of ``config.yaml`` loaded as a dict.
        """
        cfg = config_scope or {}
        allowed_domains: List[str] = cfg.get("allowed_domains", [])
        if not allowed_domains:
            parsed_seed = urlparse(seed_url)
            allowed_domains = [parsed_seed.netloc.lower()]

        return cls(
            allowed_domains=allowed_domains,
            allowed_paths=cfg.get("allowed_paths", []),
            excluded_paths=cfg.get("excluded_paths", ["/logout", "/signout", "/delete"]),
            excluded_extensions=cfg.get(
                "excluded_extensions",
                [".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                 ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip"],
            ),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Worker function (runs in thread-pool workers, pure — no Crawler state)
# ─────────────────────────────────────────────────────────────────────────────


def _fetch_and_parse(
    url: str,
    depth: int,
    requester: Requester,
    parser: HTMLParser,
    scope_guard: ScopeGuard,
    state: _CrawlState,
) -> List[Tuple[str, int]]:
    """
    Fetch a single URL, parse it, record the endpoint, and return child URLs.

    This function is designed to be called concurrently from a
    :class:`~concurrent.futures.ThreadPoolExecutor`.  All mutations to shared
    state go through ``state._lock`` to guarantee thread safety.

    Parameters
    ----------
    url : str
        The absolute URL to fetch.
    depth : int
        BFS depth of this URL (used to populate :attr:`CrawledEndpoint.depth`).
    requester : Requester
        Shared HTTP session (thread-safe for concurrent reads via urllib3 pool).
    parser : HTMLParser
        HTML parser (stateless — safe to share across threads).
    scope_guard : ScopeGuard
        Immutable scope rules (safe to share across threads).
    state : _CrawlState
        Mutable shared state protected by ``state._lock``.

    Returns
    -------
    list[tuple[str, int]]
        In-scope child ``(url, depth+1)`` pairs discovered on this page,
        filtered for deduplication against ``state.visited``.  Returns an
        empty list if this URL cannot be fetched or parsed.
    """
    logger.debug("[depth %d] Fetching: %s", depth, url)

    response, error = requester.get(url)

    if error or response is None:
        logger.warning("Failed to fetch %s: %s", url, error)
        with state._lock:
            state.result.failed_urls[url] = error or "Unknown error"
        return []

    # Only parse HTML content types.
    content_type = response.headers.get("Content-Type", "")
    if "html" not in content_type.lower():
        logger.debug("Skipping non-HTML content at %s (%s)", url, content_type)
        return []

    # ── Parse HTML ───────────────────────────────────────────────────────────
    try:
        page: ParsedPage = parser.parse(response.text, url)
    except Exception as exc:
        logger.error("Parse error at %s: %s", url, exc)
        return []

    # ── Build and record the endpoint (under lock) ────────────────────────────
    own_query_params = HTMLParser.extract_query_params(url)
    endpoint = CrawledEndpoint(
        url=url,
        status_code=response.status_code,
        depth=depth,
        forms=page.forms,
        links=page.links,
        query_params=own_query_params,
        response_headers=dict(response.headers),
    )

    with state._lock:
        # Honour the endpoint cap — don't add if already at limit.
        if state.cap_reached():
            return []
        state.result.endpoints.append(endpoint)
        logger.info(
            "  ✓ %s [HTTP %d] | forms=%d links=%d params=%d",
            url,
            response.status_code,
            len(page.forms),
            len(page.links),
            len(own_query_params),
        )

    # ── Collect in-scope child URLs ───────────────────────────────────────────
    child_depth = depth + 1
    children: List[Tuple[str, int]] = []

    for link in page.links:
        child_url = Crawler._normalise_url(link.url)

        if not scope_guard.is_in_scope(child_url):
            logger.debug("Out of scope, skipping: %s", child_url)
            continue

        with state._lock:
            if child_url in state.visited:
                continue
            # Check cap before enqueuing a new child fetch.
            if state.cap_reached():
                break
            state.visited.add(child_url)

        children.append((child_url, child_depth))
        logger.debug("  Enqueued [depth %d]: %s", child_depth, child_url)

    return children


# ─────────────────────────────────────────────────────────────────────────────
# Crawler
# ─────────────────────────────────────────────────────────────────────────────


class Crawler:
    """
    Concurrent BFS web crawler that maps the attack surface of a target app.

    The crawler fetches all URLs at the **same BFS depth level** concurrently
    using a :class:`~concurrent.futures.ThreadPoolExecutor`, then advances to
    the next depth.  This preserves correct BFS depth semantics while achieving
    ``O(max_workers)`` fetch parallelism at each level.

    Thread-safe shared state (visited set, endpoint list, failed-URL map) is
    protected by a single :class:`threading.Lock` inside :class:`_CrawlState`.

    Parameters
    ----------
    requester : Requester
        Configured HTTP session manager.  The caller is responsible for its
        lifecycle (construction and cleanup).
    parser : HTMLParser | None
        HTML parser instance.  A default is created if not provided.
        :class:`HTMLParser` is stateless and safe to share across threads.
    max_depth : int
        Maximum BFS depth.  0 means only the seed URL is fetched.
    max_workers : int
        Number of concurrent worker threads for intra-depth URL fetching.
        Defaults to ``1`` (single-threaded, matching prior behaviour).
        Set to ``requester.max_workers`` for full concurrency.
    max_endpoints : int | None
        Stop enqueuing new child URLs once this many endpoints have been
        successfully fetched.  ``None`` = unlimited.  Enforced *inside* the
        crawl loop so no unnecessary network requests are made.
    scope_guard : ScopeGuard | None
        URL scope filter.  If not provided, a guard derived from the seed
        URL's domain is constructed lazily inside :meth:`crawl`.

    Example
    -------
    >>> requester = Requester(timeout=10, rate_limit_rps=5, max_workers=10)
    >>> crawler = Crawler(requester, max_depth=3, max_workers=10)
    >>> result = crawler.crawl("https://testphp.vulnweb.com/")
    >>> print(result.summary())
    """

    def __init__(
        self,
        requester: Requester,
        parser: Optional[HTMLParser] = None,
        max_depth: int = 3,
        max_workers: int = 1,
        max_endpoints: Optional[int] = None,
        scope_guard: Optional[ScopeGuard] = None,
    ) -> None:
        self.requester = requester
        self.parser: HTMLParser = parser or HTMLParser()
        self.max_depth = max_depth
        self.max_workers = max(1, max_workers)
        self.max_endpoints = max_endpoints
        self._scope_guard = scope_guard  # May be None until crawl() is called.

    # ── Public API ───────────────────────────────────────────────────────────

    def crawl(
        self,
        seed_url: str,
        scope_config: Optional[dict] = None,
    ) -> CrawlResult:
        """
        Begin a concurrent BFS crawl from ``seed_url``.

        Fetches all URLs at each depth level in parallel, then advances to
        the next depth.  Thread-safe deduplication ensures no URL is fetched
        more than once even under concurrent conditions.

        Parameters
        ----------
        seed_url : str
            The starting URL for the crawl.
        scope_config : dict | None
            The ``scope`` section of the loaded config YAML.  If omitted, the
            crawler restricts itself to the seed URL's domain automatically.

        Returns
        -------
        CrawlResult
            Full structured crawl output.
        """
        scope_guard = self._scope_guard or ScopeGuard.from_seed(seed_url, scope_config)

        # Gate redirect following on the shared requester for the whole scan
        # (crawl + fuzz phases): an off-scope 30x must not bounce a probe onto
        # an unintended host. This is the single choke point every entry path
        # reaches before any scanning request is issued.
        self.requester.set_scope_guard(scope_guard)

        result = CrawlResult(seed_url=seed_url)

        seed_normalised = self._normalise_url(seed_url)

        # Shared mutable state — all worker mutations go through state._lock.
        state = _CrawlState(
            result=result,
            visited={seed_normalised},
            max_endpoints=self.max_endpoints,
        )

        # BFS frontier: list of (url, depth) pairs at the *current* depth.
        current_frontier: List[Tuple[str, int]] = [(seed_normalised, 0)]

        logger.info(
            "Crawl started | seed=%s | max_depth=%d | max_workers=%d | max_endpoints=%s",
            seed_url, self.max_depth, self.max_workers,
            self.max_endpoints if self.max_endpoints else "unlimited",
        )

        with ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="vdast-crawler",
        ) as pool:
            while current_frontier:
                # Check cap before dispatching the next batch.
                with state._lock:
                    if state.cap_reached():
                        logger.info(
                            "max_endpoints=%d reached — stopping crawl.",
                            self.max_endpoints,
                        )
                        break

                # Submit all URLs in the current depth batch concurrently.
                future_map: Dict[Future[List[Tuple[str, int]]], str] = {
                    pool.submit(
                        _fetch_and_parse,
                        url, depth,
                        self.requester,
                        self.parser,
                        scope_guard,
                        state,
                    ): url
                    for url, depth in current_frontier
                }

                # Collect child URLs for the next depth level.
                next_frontier: List[Tuple[str, int]] = []

                for future in as_completed(future_map):
                    try:
                        children = future.result()
                    except Exception as exc:  # noqa: BLE001
                        parent_url = future_map[future]
                        logger.error(
                            "Unexpected error fetching %s: %s", parent_url, exc
                        )
                        children = []

                    # Only enqueue children if we haven't reached max_depth.
                    for child_url, child_depth in children:
                        if child_depth <= self.max_depth:
                            next_frontier.append((child_url, child_depth))

                current_frontier = next_frontier

        logger.info(result.summary())
        return result

    # ── Private helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _normalise_url(url: str) -> str:
        """
        Strip URL fragments and trailing slashes for deduplication purposes.

        Two URLs that differ only in their ``#fragment`` portion refer to the
        same server-side resource, so we treat them as identical.
        """
        parsed = urlparse(url)
        # Remove fragment; keep query string (different params = different page).
        normalised = parsed._replace(fragment="").geturl()
        return normalised.rstrip("/") if normalised.endswith("/") else normalised

    # ── Class-level factory ──────────────────────────────────────────────────

    @classmethod
    def from_config(cls, config: dict, requester: Requester) -> "Crawler":
        """
        Construct a :class:`Crawler` from the full parsed ``config.yaml`` dict.

        Parameters
        ----------
        config : dict
            The entire YAML config loaded via ``yaml.safe_load``.
        requester : Requester
            Configured HTTP session (created separately so it can be shared
            with scanning modules).

        Returns
        -------
        Crawler
            Fully configured crawler instance.

        Example
        -------
        >>> import yaml
        >>> with open("config.yaml") as f:
        ...     cfg = yaml.safe_load(f)
        >>> requester = Requester(timeout=10, rate_limit_rps=5)
        >>> crawler = Crawler.from_config(cfg, requester)
        >>> result = crawler.crawl("https://target.example.com/")
        """
        crawler_cfg = config.get("crawler", {})
        max_depth = int(crawler_cfg.get("max_depth", 3))
        max_workers = int(crawler_cfg.get("max_workers", 1))
        raw_cap = crawler_cfg.get("max_endpoints", None)
        max_endpoints: Optional[int] = int(raw_cap) if raw_cap is not None else None

        return cls(
            requester=requester,
            max_depth=max_depth,
            max_workers=max_workers,
            max_endpoints=max_endpoints,
            # ScopeGuard is constructed lazily inside crawl() using scope_cfg,
            # so we don't need the seed URL here.
        )
