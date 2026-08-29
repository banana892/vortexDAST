"""
VortexDAST – tests/test_tier2_concurrency.py
────────────────────────────────────────────────────────────────────────────
Unit and integration tests for Tier 2 concurrency improvements.

Covers:
  • Concurrent BFS crawler correctness (deduplication, depth semantics,
    max_endpoints enforcement) using mocked Requester.
  • Thread-safety of _CrawlState under simulated race conditions.
  • Rate-limiter slot-reservation model under multithreaded contention.
  • max_slot_wait safety guard in Requester._apply_rate_limit.
  • Parallel fuzz loop in scanner.run_scan (exception isolation, findings
    aggregation, progress bar advancing).

All tests are fully offline — no live network required.

Run with:
    pytest tests/test_tier2_concurrency.py -v
"""

from __future__ import annotations

import sys
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crawler import (
    Crawler,
    CrawlResult,
    CrawledEndpoint,
    ScopeGuard,
    _CrawlState,
    _fetch_and_parse,
)
from core.requester import Requester


# ─────────────────────────────────────────────────────────────────────────────
# Shared HTML fixtures
# ─────────────────────────────────────────────────────────────────────────────

_SEED_HTML = """
<!DOCTYPE html>
<html>
<body>
  <a href="/page-a">Page A</a>
  <a href="/page-b">Page B</a>
  <a href="/page-c">Page C</a>
  <form action="/form" method="POST">
    <input type="text" name="q" value="">
    <input type="submit" value="Go">
  </form>
</body>
</html>
"""

_CHILD_HTML = """
<!DOCTYPE html><html><body><p>Leaf page</p></body></html>
"""


def _html_response(html: str, url: str = "http://target.com/") -> MagicMock:
    """Minimal mock of ``requests.Response`` returning HTML content."""
    resp = MagicMock()
    resp.status_code = 200
    resp.text = html
    resp.content = html.encode()
    resp.headers = {"Content-Type": "text/html; charset=utf-8"}
    resp.url = url
    return resp


def _error_response() -> tuple:
    """Return the (None, error_msg) pair that Requester returns on failure."""
    return None, "Connection refused"


def _make_mock_requester(url_to_html: dict) -> MagicMock:
    """
    Build a MagicMock Requester whose ``.get()`` returns HTML responses
    keyed by URL, or an error tuple for unknown URLs.
    """
    req = MagicMock(spec=Requester)
    req.max_workers = 4

    def _get(url: str, **kwargs):
        # Strip trailing slash for lookup consistency.
        key = url.rstrip("/")
        html = url_to_html.get(key) or url_to_html.get(url)
        if html is None:
            return None, f"No mock for {url}"
        return _html_response(html, url=url), None

    req.get.side_effect = _get
    return req


# ─────────────────────────────────────────────────────────────────────────────
# _CrawlState tests
# ─────────────────────────────────────────────────────────────────────────────


class TestCrawlState:
    """Verify the thread-safe shared state container."""

    def test_cap_not_reached_when_max_endpoints_is_none(self) -> None:
        result = CrawlResult(seed_url="http://x.com")
        state = _CrawlState(result=result, visited=set(), max_endpoints=None)
        assert not state.cap_reached()

    def test_cap_not_reached_below_limit(self) -> None:
        result = CrawlResult(seed_url="http://x.com")
        result.endpoints.append(
            CrawledEndpoint(url="http://x.com/a", status_code=200, depth=0)
        )
        state = _CrawlState(result=result, visited=set(), max_endpoints=5)
        assert not state.cap_reached()

    def test_cap_reached_at_limit(self) -> None:
        result = CrawlResult(seed_url="http://x.com")
        for i in range(3):
            result.endpoints.append(
                CrawledEndpoint(url=f"http://x.com/{i}", status_code=200, depth=0)
            )
        state = _CrawlState(result=result, visited=set(), max_endpoints=3)
        assert state.cap_reached()

    def test_endpoint_count_reflects_result(self) -> None:
        result = CrawlResult(seed_url="http://x.com")
        state = _CrawlState(result=result, visited=set(), max_endpoints=None)
        assert state.endpoint_count == 0
        result.endpoints.append(
            CrawledEndpoint(url="http://x.com/", status_code=200, depth=0)
        )
        assert state.endpoint_count == 1

    def test_concurrent_appends_are_thread_safe(self) -> None:
        """Appending to result.endpoints from N threads under lock yields N items."""
        result = CrawlResult(seed_url="http://x.com")
        state = _CrawlState(result=result, visited=set(), max_endpoints=None)
        n = 50

        def _append(i: int) -> None:
            ep = CrawledEndpoint(url=f"http://x.com/{i}", status_code=200, depth=0)
            with state._lock:
                result.endpoints.append(ep)

        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(_append, range(n)))

        assert len(result.endpoints) == n
        urls = {ep.url for ep in result.endpoints}
        assert len(urls) == n  # no duplicates


# ─────────────────────────────────────────────────────────────────────────────
# Concurrent BFS Crawler tests
# ─────────────────────────────────────────────────────────────────────────────


class TestConcurrentCrawler:
    """Verify correctness of the concurrent BFS Crawler."""

    def _build_url_map(self) -> dict:
        return {
            "http://target.com": _SEED_HTML,
            "http://target.com/page-a": _CHILD_HTML,
            "http://target.com/page-b": _CHILD_HTML,
            "http://target.com/page-c": _CHILD_HTML,
        }

    def test_crawl_returns_crawl_result(self) -> None:
        req = _make_mock_requester(self._build_url_map())
        crawler = Crawler(req, max_depth=1, max_workers=2)
        result = crawler.crawl("http://target.com")
        assert isinstance(result, CrawlResult)
        assert result.seed_url == "http://target.com"

    def test_crawl_fetches_seed_endpoint(self) -> None:
        req = _make_mock_requester(self._build_url_map())
        crawler = Crawler(req, max_depth=0, max_workers=1)
        result = crawler.crawl("http://target.com")
        assert len(result.endpoints) == 1
        assert result.endpoints[0].url == "http://target.com"

    def test_concurrent_crawl_discovers_child_links(self) -> None:
        """With max_depth=1 and 3 child links, 4 endpoints should be found."""
        req = _make_mock_requester(self._build_url_map())
        crawler = Crawler(req, max_depth=1, max_workers=4)
        result = crawler.crawl("http://target.com")
        assert len(result.endpoints) == 4
        urls = {ep.url for ep in result.endpoints}
        assert "http://target.com" in urls
        assert "http://target.com/page-a" in urls
        assert "http://target.com/page-b" in urls
        assert "http://target.com/page-c" in urls

    def test_no_duplicate_endpoints_under_concurrent_crawl(self) -> None:
        """Each URL must appear exactly once in result.endpoints."""
        req = _make_mock_requester(self._build_url_map())
        crawler = Crawler(req, max_depth=1, max_workers=8)
        result = crawler.crawl("http://target.com")
        urls = [ep.url for ep in result.endpoints]
        assert len(urls) == len(set(urls)), f"Duplicates found: {urls}"

    def test_crawl_respects_max_depth_zero(self) -> None:
        """max_depth=0 means only the seed URL is fetched."""
        req = _make_mock_requester(self._build_url_map())
        crawler = Crawler(req, max_depth=0, max_workers=4)
        result = crawler.crawl("http://target.com")
        assert len(result.endpoints) == 1

    def test_crawl_respects_max_depth_one(self) -> None:
        """max_depth=1 fetches seed + direct children only."""
        # Seed has 3 children; children have no further links in _CHILD_HTML.
        req = _make_mock_requester(self._build_url_map())
        crawler = Crawler(req, max_depth=1, max_workers=4)
        result = crawler.crawl("http://target.com")
        depths = {ep.depth for ep in result.endpoints}
        assert max(depths) <= 1

    def test_max_endpoints_stops_crawl_early(self) -> None:
        """With max_endpoints=2, crawler must not exceed 2 endpoints."""
        req = _make_mock_requester(self._build_url_map())
        crawler = Crawler(req, max_depth=1, max_workers=4, max_endpoints=2)
        result = crawler.crawl("http://target.com")
        assert len(result.endpoints) <= 2

    def test_max_endpoints_none_means_unlimited(self) -> None:
        """max_endpoints=None fetches all reachable endpoints."""
        req = _make_mock_requester(self._build_url_map())
        crawler = Crawler(req, max_depth=1, max_workers=4, max_endpoints=None)
        result = crawler.crawl("http://target.com")
        assert len(result.endpoints) == 4

    def test_max_endpoints_one_fetches_only_seed(self) -> None:
        """max_endpoints=1 should stop after the seed URL."""
        req = _make_mock_requester(self._build_url_map())
        crawler = Crawler(req, max_depth=3, max_workers=4, max_endpoints=1)
        result = crawler.crawl("http://target.com")
        assert len(result.endpoints) == 1

    def test_failed_url_recorded_not_in_endpoints(self) -> None:
        """URLs that 404 should appear in failed_urls, not in endpoints."""
        url_map = {
            "http://target.com": _SEED_HTML,
            "http://target.com/page-a": None,  # will trigger error response
            "http://target.com/page-b": _CHILD_HTML,
            "http://target.com/page-c": _CHILD_HTML,
        }
        req = _make_mock_requester(url_map)
        crawler = Crawler(req, max_depth=1, max_workers=4)
        result = crawler.crawl("http://target.com")

        endpoint_urls = {ep.url for ep in result.endpoints}
        assert "http://target.com/page-a" not in endpoint_urls
        assert "http://target.com/page-a" in result.failed_urls

    def test_out_of_scope_links_not_followed(self) -> None:
        """External links should not be enqueued by ScopeGuard."""
        html_with_external = """
        <html><body>
          <a href="https://evil.com/steal">External</a>
          <a href="/safe">Safe</a>
        </body></html>
        """
        req = _make_mock_requester({
            "http://target.com": html_with_external,
            "http://target.com/safe": _CHILD_HTML,
        })
        crawler = Crawler(req, max_depth=1, max_workers=2)
        result = crawler.crawl("http://target.com")
        urls = {ep.url for ep in result.endpoints}
        assert not any("evil.com" in u for u in urls)

    def test_single_worker_matches_sequential_behaviour(self) -> None:
        """max_workers=1 should behave identically to the original sequential crawler."""
        req = _make_mock_requester(self._build_url_map())
        crawler = Crawler(req, max_depth=1, max_workers=1)
        result = crawler.crawl("http://target.com")
        assert len(result.endpoints) == 4

    def test_forms_attached_to_endpoint(self) -> None:
        """Forms parsed on a page must be stored on the CrawledEndpoint."""
        req = _make_mock_requester({"http://target.com": _SEED_HTML})
        crawler = Crawler(req, max_depth=0, max_workers=1)
        result = crawler.crawl("http://target.com")
        assert len(result.endpoints) == 1
        ep = result.endpoints[0]
        # _SEED_HTML has one form
        assert len(ep.forms) == 1

    def test_non_html_response_not_added_as_endpoint(self) -> None:
        """Non-HTML content-type responses must be skipped."""
        req = MagicMock(spec=Requester)
        req.max_workers = 1
        json_resp = MagicMock()
        json_resp.status_code = 200
        json_resp.headers = {"Content-Type": "application/json"}
        json_resp.text = "{}"
        req.get.return_value = (json_resp, None)

        crawler = Crawler(req, max_depth=0, max_workers=1)
        result = crawler.crawl("http://target.com")
        assert len(result.endpoints) == 0

    def test_from_config_passes_max_workers_and_max_endpoints(self) -> None:
        """Crawler.from_config() must correctly wire max_workers and max_endpoints."""
        config = {
            "crawler": {"max_depth": 2, "max_workers": 8, "max_endpoints": 50},
            "scope": {},
        }
        req = MagicMock(spec=Requester)
        req.max_workers = 8
        crawler = Crawler.from_config(config, req)
        assert crawler.max_depth == 2
        assert crawler.max_workers == 8
        assert crawler.max_endpoints == 50

    def test_from_config_null_max_endpoints_gives_none(self) -> None:
        """max_endpoints: null in YAML should produce None (unlimited)."""
        config = {"crawler": {"max_depth": 3, "max_workers": 4, "max_endpoints": None}}
        req = MagicMock(spec=Requester)
        req.max_workers = 4
        crawler = Crawler.from_config(config, req)
        assert crawler.max_endpoints is None


# ─────────────────────────────────────────────────────────────────────────────
# Rate-limiter thread-safety tests
# ─────────────────────────────────────────────────────────────────────────────


class TestRateLimiterThreadSafety:
    """
    Verify _apply_rate_limit behaves correctly under concurrent access.

    We test the slot-reservation model without making real HTTP calls.
    """

    def _make_requester(self, rps: float, max_slot_wait: float = 60.0) -> Requester:
        """Build a Requester with rate-limiting and no real network."""
        req = Requester(
            rate_limit_rps=rps,
            max_slot_wait=max_slot_wait,
            max_workers=20,
        )
        # Prevent the session from making real requests.
        req.session.request = MagicMock(side_effect=RuntimeError("no network"))
        return req

    def test_no_rate_limit_returns_immediately(self) -> None:
        req = Requester(rate_limit_rps=0.0)
        t0 = time.monotonic()
        req._apply_rate_limit()
        elapsed = time.monotonic() - t0
        assert elapsed < 0.05, f"Expected near-zero wait, got {elapsed:.3f}s"
        req.close()

    def test_single_thread_respects_interval(self) -> None:
        """Two sequential _apply_rate_limit calls must be ≥ interval apart."""
        rps = 10.0
        req = self._make_requester(rps)
        t0 = time.monotonic()
        req._apply_rate_limit()
        req._apply_rate_limit()
        elapsed = time.monotonic() - t0
        min_expected = 1.0 / rps
        assert elapsed >= min_expected * 0.85, (
            f"Expected ≥{min_expected:.3f}s, got {elapsed:.3f}s"
        )
        req.close()

    def test_concurrent_threads_reserve_staggered_slots(self) -> None:
        """
        N threads all calling _apply_rate_limit simultaneously must produce
        staggered sleeps — total elapsed ≥ (N-1) × interval.
        """
        n_threads = 5
        rps = 20.0  # 50 ms per slot
        interval = 1.0 / rps
        req = self._make_requester(rps)

        start_times: List[float] = []
        barrier = threading.Barrier(n_threads)

        def _worker() -> None:
            barrier.wait()  # All threads start simultaneously.
            t = time.monotonic()
            req._apply_rate_limit()
            start_times.append(time.monotonic() - t)

        threads = [threading.Thread(target=_worker) for _ in range(n_threads)]
        t_global = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        total_elapsed = time.monotonic() - t_global

        # All N slots must be staggered: total wall time ≥ (N-1) × interval.
        min_wall = (n_threads - 1) * interval
        assert total_elapsed >= min_wall * 0.85, (
            f"Slots may not be staggered: expected ≥{min_wall:.3f}s, "
            f"got {total_elapsed:.3f}s"
        )
        req.close()

    def test_max_slot_wait_raises_runtime_error(self) -> None:
        """
        When the computed slot wait exceeds max_slot_wait, RuntimeError must
        be raised instead of sleeping.
        """
        # Set an extremely low max_slot_wait so it triggers quickly.
        req = self._make_requester(rps=1.0, max_slot_wait=0.001)
        # First call reserves t=0 → t=1s.  Second call would sleep ~1s > 0.001s.
        req._apply_rate_limit()  # slot 0 — likely 0 sleep
        with pytest.raises(RuntimeError, match="max_slot_wait"):
            req._apply_rate_limit()  # slot 1 — sleep ≈ 1s > 0.001s guard
        req.close()

    def test_no_duplicate_slots_under_race(self) -> None:
        """
        Under contention, no two threads should receive the same slot
        (each call to _apply_rate_limit must advance _last_request_time).
        """
        rps = 100.0  # fast enough to complete quickly
        req = self._make_requester(rps, max_slot_wait=60.0)
        n = 20
        barrier = threading.Barrier(n)
        slot_times: List[float] = []
        lock = threading.Lock()

        def _grab_slot() -> None:
            barrier.wait()
            with req._rate_lock:
                now = time.monotonic()
                t = max(now, req._last_request_time) + req._min_interval
                req._last_request_time = t
            with lock:
                slot_times.append(t)

        threads = [threading.Thread(target=_grab_slot) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All slots must be unique (rounded to sub-millisecond).
        unique_slots = {round(t, 6) for t in slot_times}
        assert len(unique_slots) == n, (
            f"Expected {n} unique slots, got {len(unique_slots)}"
        )
        req.close()


# ─────────────────────────────────────────────────────────────────────────────
# Parallel fuzz loop (scanner.run_scan) tests
# ─────────────────────────────────────────────────────────────────────────────


class TestParallelFuzz:
    """
    Verify the parallel endpoint-fuzzing loop in scanner.run_scan.

    We mock out all I/O (Requester, Crawler, Reporter) and focus purely on
    the concurrency behaviour of the fuzz phase.
    """

    def _make_endpoint(self, url: str) -> CrawledEndpoint:
        return CrawledEndpoint(url=url, status_code=200, depth=0)

    def _make_finding(self, url: str):
        from modules.base import Finding, Severity
        return Finding(title="Test", severity=Severity.LOW, url=url)

    def test_all_endpoints_probed(self) -> None:
        """Every endpoint must be probed by each module exactly once."""
        from modules.base import BaseScannerModule, Finding

        probe_calls: List[str] = []
        lock = threading.Lock()

        class _CountingModule(BaseScannerModule):
            name = "counting"
            description = "Counts calls."

            def run(self, endpoint):
                with lock:
                    probe_calls.append(endpoint.url)
                return []

        endpoints = [self._make_endpoint(f"http://t.com/{i}") for i in range(6)]
        module = _CountingModule(MagicMock(spec=Requester))

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(module.run, ep): ep for ep in endpoints}
            results = []
            for future in futures:
                results.extend(future.result())

        assert sorted(probe_calls) == sorted(ep.url for ep in endpoints)

    def test_exception_in_one_endpoint_does_not_abort_others(self) -> None:
        """A RuntimeError on one endpoint must not prevent others from completing."""
        from modules.base import BaseScannerModule, Finding, Severity

        completed: List[str] = []
        lock = threading.Lock()

        class _FlakyModule(BaseScannerModule):
            name = "flaky"
            description = "Raises on /bad."

            def run(self, endpoint):
                if "/bad" in endpoint.url:
                    raise RuntimeError("Simulated network timeout")
                with lock:
                    completed.append(endpoint.url)
                return [Finding(title="X", severity=Severity.LOW, url=endpoint.url)]

        good_eps = [self._make_endpoint(f"http://t.com/good{i}") for i in range(5)]
        bad_ep = self._make_endpoint("http://t.com/bad")
        all_eps = good_eps + [bad_ep]

        module = _FlakyModule(MagicMock(spec=Requester))
        all_findings: List[Finding] = []
        errors: List[str] = []

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(module.run, ep): ep for ep in all_eps}
            for future in futures:
                try:
                    all_findings.extend(future.result())
                except Exception as exc:
                    errors.append(str(exc))

        # Good endpoints ran to completion.
        assert sorted(completed) == sorted(ep.url for ep in good_eps)
        # Exactly one error was recorded.
        assert len(errors) == 1
        assert "Simulated network timeout" in errors[0]
        # Good findings were collected.
        assert len(all_findings) == len(good_eps)

    def test_findings_from_all_threads_aggregated(self) -> None:
        """Findings returned from concurrent workers must all be collected."""
        from modules.base import BaseScannerModule, Finding, Severity

        class _AlwaysFindModule(BaseScannerModule):
            name = "always_find"
            description = "Always returns one finding."

            def run(self, endpoint):
                return [Finding(
                    title="Always",
                    severity=Severity.HIGH,
                    url=endpoint.url,
                )]

        n = 12
        endpoints = [self._make_endpoint(f"http://t.com/{i}") for i in range(n)]
        module = _AlwaysFindModule(MagicMock(spec=Requester))
        all_findings: List[Finding] = []
        findings_lock = threading.Lock()

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {pool.submit(module.run, ep): ep for ep in endpoints}
            for future in futures:
                with findings_lock:
                    all_findings.extend(future.result())

        assert len(all_findings) == n
        finding_urls = {f.url for f in all_findings}
        assert finding_urls == {ep.url for ep in endpoints}

    def test_findings_lock_prevents_data_races(self) -> None:
        """
        Simulates concurrent extend() calls; verifies final count is correct
        (detects lost-update bugs that would occur without the lock).
        """
        combined: List[int] = []
        lock = threading.Lock()
        n_threads = 20
        items_per_thread = 100

        def _extend_batch(items: List[int]) -> None:
            with lock:
                combined.extend(items)

        with ThreadPoolExecutor(max_workers=n_threads) as pool:
            futs = [
                pool.submit(_extend_batch, list(range(items_per_thread)))
                for _ in range(n_threads)
            ]
            for f in futs:
                f.result()

        assert len(combined) == n_threads * items_per_thread


# ─────────────────────────────────────────────────────────────────────────────
# _fetch_and_parse unit tests
# ─────────────────────────────────────────────────────────────────────────────


class TestFetchAndParse:
    """Unit tests for the _fetch_and_parse worker function."""

    def _make_state(
        self,
        seed: str = "http://t.com",
        max_endpoints: Optional[int] = None,
    ) -> _CrawlState:
        return _CrawlState(
            result=CrawlResult(seed_url=seed),
            visited={seed},
            max_endpoints=max_endpoints,
        )

    def test_successful_fetch_appends_endpoint(self) -> None:
        from core.parser import HTMLParser

        req = MagicMock(spec=Requester)
        req.get.return_value = (
            _html_response("<html><body><p>OK</p></body></html>", "http://t.com"),
            None,
        )
        scope = ScopeGuard.from_seed("http://t.com")
        state = self._make_state()

        _fetch_and_parse("http://t.com", 0, req, HTMLParser(), scope, state)

        assert len(state.result.endpoints) == 1
        assert state.result.endpoints[0].url == "http://t.com"

    def test_fetch_error_recorded_in_failed_urls(self) -> None:
        from core.parser import HTMLParser

        req = MagicMock(spec=Requester)
        req.get.return_value = (None, "Connection refused")
        scope = ScopeGuard.from_seed("http://t.com")
        state = self._make_state()

        _fetch_and_parse("http://t.com/bad", 0, req, HTMLParser(), scope, state)

        assert len(state.result.endpoints) == 0
        assert "http://t.com/bad" in state.result.failed_urls

    def test_cap_reached_prevents_endpoint_append(self) -> None:
        from core.parser import HTMLParser

        req = MagicMock(spec=Requester)
        req.get.return_value = (
            _html_response("<html><body></body></html>", "http://t.com/b"),
            None,
        )
        scope = ScopeGuard.from_seed("http://t.com")
        # Pre-fill result to hit the cap.
        state = self._make_state(max_endpoints=1)
        state.result.endpoints.append(
            CrawledEndpoint(url="http://t.com/a", status_code=200, depth=0)
        )
        assert state.cap_reached()

        children = _fetch_and_parse(
            "http://t.com/b", 1, req, HTMLParser(), scope, state
        )

        # Endpoint not appended — cap was already reached.
        assert len(state.result.endpoints) == 1
        # No children returned when cap is reached.
        assert children == []

    def test_child_urls_returned(self) -> None:
        from core.parser import HTMLParser

        html = '<html><body><a href="/child">C</a></body></html>'
        req = MagicMock(spec=Requester)
        req.get.return_value = (_html_response(html, "http://t.com"), None)
        scope = ScopeGuard.from_seed("http://t.com")
        state = self._make_state()

        children = _fetch_and_parse("http://t.com", 0, req, HTMLParser(), scope, state)

        child_urls = [url for url, _ in children]
        assert "http://t.com/child" in child_urls

    def test_already_visited_child_not_returned(self) -> None:
        from core.parser import HTMLParser

        html = '<html><body><a href="/child">C</a></body></html>'
        req = MagicMock(spec=Requester)
        req.get.return_value = (_html_response(html, "http://t.com"), None)
        scope = ScopeGuard.from_seed("http://t.com")
        # Pre-mark /child as visited.
        state = self._make_state()
        state.visited.add("http://t.com/child")

        children = _fetch_and_parse("http://t.com", 0, req, HTMLParser(), scope, state)

        assert not any(u == "http://t.com/child" for u, _ in children)
