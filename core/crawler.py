"""
VortexDAST – core/crawler.py
────────────────────────────────────────────────────────────────────────────
Static BFS (Breadth-First Search) web crawler.

Responsibilities:
  • Accept a seed URL and discover all reachable endpoints within the
    configured scope (allowed domains, allowed/excluded paths, excluded file
    extensions).
  • Use the Requester for HTTP and the HTMLParser for link/form extraction.
  • Enforce a configurable maximum crawl depth.
  • Collect and deduplicate every discovered URL, form, and query parameter
    set into a structured :class:`CrawlResult`.
  • Respect the scope rules defined in ``config.yaml`` so we never wander
    outside the target application.

This module implements *static* crawling only (plain HTTP + BeautifulSoup).
Dynamic JS-rendered crawling via Playwright lives in ``core/dom_watcher.py``
(Phase 3) and can be composed with this crawler.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from .parser import HTMLParser, ParsedForm, ParsedLink, ParsedPage
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

    forms: List[ParsedForm] = field(default_factory=list)
    """All HTML forms found on this page."""

    links: List[ParsedLink] = field(default_factory=list)
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

        If ``config_scope["allowed_domains"]`` is empty, the seed URL's netloc
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
# Crawler
# ─────────────────────────────────────────────────────────────────────────────


class Crawler:
    """
    Static BFS web crawler that maps the attack surface of a target application.

    The crawler:
      1. Fetches the seed URL and parses its HTML.
      2. Enqueues all in-scope links discovered on each page.
      3. Repeats until the BFS queue is empty or ``max_depth`` is reached.
      4. Returns a :class:`CrawlResult` containing every discovered endpoint
         and its associated forms, links, and query parameters.

    Parameters
    ----------
    requester : Requester
        Configured HTTP session manager.  The caller is responsible for its
        lifecycle (construction and cleanup).
    parser : HTMLParser | None
        HTML parser instance.  A default is created if not provided.
    max_depth : int
        Maximum BFS depth.  0 means only the seed URL is fetched.
    scope_guard : ScopeGuard | None
        URL scope filter.  If not provided, a guard derived from the seed
        URL's domain is used automatically.

    Example
    -------
    >>> requester = Requester(timeout=10, rate_limit_rps=5)
    >>> crawler = Crawler(requester, max_depth=3)
    >>> result = crawler.crawl("https://testphp.vulnweb.com/")
    >>> print(result.summary())
    """

    def __init__(
        self,
        requester: Requester,
        parser: Optional[HTMLParser] = None,
        max_depth: int = 3,
        scope_guard: Optional[ScopeGuard] = None,
    ) -> None:
        self.requester = requester
        self.parser: HTMLParser = parser or HTMLParser()
        self.max_depth = max_depth
        self._scope_guard = scope_guard  # May be None until crawl() is called.

    # ── Public API ───────────────────────────────────────────────────────────

    def crawl(
        self,
        seed_url: str,
        scope_config: Optional[dict] = None,
    ) -> CrawlResult:
        """
        Begin a BFS crawl from ``seed_url``.

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
        # Initialise or derive the scope guard for this run.
        scope_guard = self._scope_guard or ScopeGuard.from_seed(seed_url, scope_config)

        result = CrawlResult(seed_url=seed_url)

        # BFS queue items: (url, depth)
        queue: deque[tuple[str, int]] = deque()
        visited: Set[str] = set()

        # Normalise the seed URL (strip fragment) and enqueue it.
        seed_normalised = self._normalise_url(seed_url)
        queue.append((seed_normalised, 0))
        visited.add(seed_normalised)

        logger.info("Crawl started | seed=%s | max_depth=%d", seed_url, self.max_depth)

        while queue:
            current_url, depth = queue.popleft()

            logger.info("[depth %d] Fetching: %s", depth, current_url)

            # ── Fetch the page ────────────────────────────────────────────
            response, error = self.requester.get(current_url)

            if error or response is None:
                logger.warning("Failed to fetch %s: %s", current_url, error)
                result.failed_urls[current_url] = error or "Unknown error"
                continue

            # Only parse HTML content types.
            content_type = response.headers.get("Content-Type", "")
            if "html" not in content_type.lower():
                logger.debug("Skipping non-HTML content at %s (%s)", current_url, content_type)
                continue

            # ── Parse the HTML ────────────────────────────────────────────
            try:
                page: ParsedPage = self.parser.parse(response.text, current_url)
            except Exception as exc:
                logger.error("Parse error at %s: %s", current_url, exc)
                continue

            # ── Build endpoint record ─────────────────────────────────────
            own_query_params = HTMLParser.extract_query_params(current_url)
            endpoint = CrawledEndpoint(
                url=current_url,
                status_code=response.status_code,
                depth=depth,
                forms=page.forms,
                links=page.links,
                query_params=own_query_params,
                response_headers=dict(response.headers),
            )
            result.endpoints.append(endpoint)

            logger.info(
                "  ✓ %s [HTTP %d] | forms=%d links=%d params=%d",
                current_url,
                response.status_code,
                len(page.forms),
                len(page.links),
                len(own_query_params),
            )

            # ── Enqueue child links ───────────────────────────────────────
            if depth < self.max_depth:
                for link in page.links:
                    child_url = self._normalise_url(link.url)

                    if child_url in visited:
                        continue
                    if not scope_guard.is_in_scope(child_url):
                        logger.debug("Out of scope, skipping: %s", child_url)
                        continue

                    visited.add(child_url)
                    queue.append((child_url, depth + 1))
                    logger.debug("  Enqueued [depth %d]: %s", depth + 1, child_url)

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
        >>> requester = Requester.from_config(cfg)  # hypothetical factory
        >>> crawler = Crawler.from_config(cfg, requester)
        >>> result = crawler.crawl("https://target.example.com/")
        """
        crawler_cfg = config.get("crawler", {})
        max_depth = int(crawler_cfg.get("max_depth", 3))

        scope_cfg = config.get("scope", {})

        return cls(
            requester=requester,
            max_depth=max_depth,
            # ScopeGuard is constructed lazily inside crawl() using scope_cfg,
            # so we don't need the seed URL here.
        )
