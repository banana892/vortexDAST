"""
VortexDAST – tests/test_crawler.py
────────────────────────────────────────────────────────────────────────────
Unit tests for core/crawler.py and core/parser.py.

Uses ``unittest.mock`` to stub out the network layer (Requester) so that
tests run offline without requiring a live target.

Run with:
    pytest tests/test_crawler.py -v
"""

from __future__ import annotations

import sys
import os

# Allow imports from the project root when running tests directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import pytest

from core.crawler import Crawler, CrawlResult, CrawledEndpoint, ScopeGuard
from core.parser import HTMLParser, ParsedForm, FormField, ParsedLink, ParsedPage
from core.requester import Requester


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

SIMPLE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
  <a href="/about">About</a>
  <a href="https://external.com/page">External</a>
  <a href="/products?id=1&cat=books">Products</a>
  <a href="#section">Fragment Only</a>
  <a href="javascript:void(0)">JS Link</a>

  <form action="/login" method="POST">
    <input type="text"     name="username" value="">
    <input type="password" name="password" value="">
    <input type="hidden"   name="csrf"     value="abc123">
    <input type="submit"   value="Log in">
  </form>

  <form action="/search" method="GET">
    <input type="text" name="q" value="default">
    <select name="category">
      <option value="all">All</option>
      <option value="news" selected>News</option>
    </select>
    <textarea name="comment">Hello</textarea>
  </form>
</body>
</html>
"""


def _make_mock_response(html: str, status: int = 200, url: str = "http://target.com/") -> MagicMock:
    """Return a minimal mock ``requests.Response`` object."""
    resp = MagicMock()
    resp.status_code = status
    resp.text = html
    resp.content = html.encode()
    resp.headers = {"Content-Type": "text/html; charset=utf-8"}
    resp.url = url
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# HTMLParser tests
# ─────────────────────────────────────────────────────────────────────────────

class TestHTMLParser:

    def setup_method(self) -> None:
        self.parser = HTMLParser()
        self.base_url = "http://target.com/"

    def test_parse_returns_parsed_page(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        assert isinstance(page, ParsedPage)
        assert page.page_url == self.base_url

    # ── Link extraction ──────────────────────────────────────────────────────

    def test_extracts_internal_links(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        urls = [link.url for link in page.links]
        assert "http://target.com/about" in urls

    def test_extracts_external_links(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        urls = [link.url for link in page.links]
        assert "https://external.com/page" in urls

    def test_resolves_relative_links(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        urls = [link.url for link in page.links]
        assert "http://target.com/products" in urls or \
               "http://target.com/products?id=1&cat=books" in urls

    def test_skips_fragment_only_anchors(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        urls = [link.url for link in page.links]
        assert not any("#section" in u for u in urls)

    def test_skips_javascript_links(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        urls = [link.url for link in page.links]
        assert not any(u.startswith("javascript:") for u in urls)

    def test_deduplicates_links(self) -> None:
        duplicate_html = SIMPLE_HTML + '<a href="/about">About again</a>'
        page = self.parser.parse(duplicate_html, self.base_url)
        about_links = [l for l in page.links if l.url == "http://target.com/about"]
        assert len(about_links) == 1

    # ── Query param extraction ────────────────────────────────────────────────

    def test_extracts_query_params_from_url(self) -> None:
        params = HTMLParser.extract_query_params("http://target.com/search?q=hello&page=2")
        assert params["q"] == ["hello"]
        assert params["page"] == ["2"]

    def test_empty_query_params_on_plain_url(self) -> None:
        params = HTMLParser.extract_query_params("http://target.com/about")
        assert params == {}

    def test_link_with_params_populates_query_params(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        product_link = next(
            (l for l in page.links if "products" in l.url), None
        )
        assert product_link is not None
        assert "id" in product_link.query_params
        assert "cat" in product_link.query_params

    # ── Form extraction ──────────────────────────────────────────────────────

    def test_extracts_two_forms(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        assert len(page.forms) == 2

    def test_login_form_method_and_action(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        login_form = next(f for f in page.forms if "/login" in f.action_url)
        assert login_form.method == "POST"
        assert login_form.action_url == "http://target.com/login"

    def test_login_form_fields(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        login_form = next(f for f in page.forms if "/login" in f.action_url)
        field_names = [f.name for f in login_form.fields]
        # submit input should be skipped
        assert "username" in field_names
        assert "password" in field_names
        assert "csrf"     in field_names
        assert len(field_names) == 3

    def test_hidden_field_type(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        login_form = next(f for f in page.forms if "/login" in f.action_url)
        csrf_field = next(f for f in login_form.fields if f.name == "csrf")
        assert csrf_field.field_type == "hidden"
        assert csrf_field.default_value == "abc123"

    def test_search_form_get_method(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        search_form = next(f for f in page.forms if "/search" in f.action_url)
        assert search_form.method == "GET"

    def test_select_field_captures_selected_option(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        search_form = next(f for f in page.forms if "/search" in f.action_url)
        cat_field = next(f for f in search_form.fields if f.name == "category")
        assert cat_field.field_type == "select"
        assert cat_field.default_value == "news"

    def test_textarea_field(self) -> None:
        page = self.parser.parse(SIMPLE_HTML, self.base_url)
        search_form = next(f for f in page.forms if "/search" in f.action_url)
        comment = next(f for f in search_form.fields if f.name == "comment")
        assert comment.field_type == "textarea"
        assert comment.default_value == "Hello"

    def test_form_with_missing_action_defaults_to_page_url(self) -> None:
        html = '<form method="POST"><input name="x"></form>'
        page = self.parser.parse(html, "http://target.com/profile")
        assert page.forms[0].action_url == "http://target.com/profile"

    def test_form_with_missing_method_defaults_to_get(self) -> None:
        html = '<form action="/go"><input name="x"></form>'
        page = self.parser.parse(html, self.base_url)
        assert page.forms[0].method == "GET"

    def test_empty_html_returns_empty_page(self) -> None:
        page = self.parser.parse("", self.base_url)
        assert page.forms == []
        assert page.links == []

    def test_file_input_kept_as_file_field(self) -> None:
        """
        A <input type="file"> must survive extraction (field_type="file") —
        modules/file_upload_check.py needs it to find upload forms at all.
        Submit/button/reset/image inputs remain excluded.
        """
        html = (
            '<form action="/upload" method="POST" enctype="multipart/form-data">'
            '<input type="file" name="avatar">'
            '<input type="submit" value="Go">'
            "</form>"
        )
        page = self.parser.parse(html, self.base_url)
        field_names = [f.name for f in page.forms[0].fields]
        assert field_names == ["avatar"]
        assert page.forms[0].fields[0].field_type == "file"


# ─────────────────────────────────────────────────────────────────────────────
# ScopeGuard tests
# ─────────────────────────────────────────────────────────────────────────────

class TestScopeGuard:

    def _guard(self, **kwargs) -> ScopeGuard:
        return ScopeGuard(
            allowed_domains=["target.com"],
            **kwargs,
        )

    def test_allows_in_scope_url(self) -> None:
        guard = self._guard()
        assert guard.is_in_scope("http://target.com/page") is True

    def test_blocks_external_domain(self) -> None:
        guard = self._guard()
        assert guard.is_in_scope("http://evil.com/page") is False

    def test_blocks_excluded_path(self) -> None:
        guard = self._guard(excluded_paths=["/logout"])
        assert guard.is_in_scope("http://target.com/logout") is False

    def test_allows_non_excluded_path(self) -> None:
        guard = self._guard(excluded_paths=["/logout"])
        assert guard.is_in_scope("http://target.com/dashboard") is True

    def test_blocks_excluded_extension(self) -> None:
        guard = self._guard(excluded_extensions=[".png"])
        assert guard.is_in_scope("http://target.com/logo.png") is False

    def test_allows_non_excluded_extension(self) -> None:
        guard = self._guard(excluded_extensions=[".png"])
        assert guard.is_in_scope("http://target.com/page.html") is True

    def test_respects_allowed_paths_whitelist(self) -> None:
        guard = self._guard(allowed_paths=["/app/"])
        assert guard.is_in_scope("http://target.com/app/dashboard") is True
        assert guard.is_in_scope("http://target.com/admin/secret") is False

    def test_blocks_javascript_scheme(self) -> None:
        guard = self._guard()
        assert guard.is_in_scope("javascript:void(0)") is False

    def test_from_seed_auto_derives_domain(self) -> None:
        guard = ScopeGuard.from_seed("http://myapp.local/start")
        assert guard.is_in_scope("http://myapp.local/other") is True
        assert guard.is_in_scope("http://other.local/page") is False


# ─────────────────────────────────────────────────────────────────────────────
# Crawler tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCrawler:
    """
    Tests for the BFS crawler logic using a mocked Requester.

    The strategy is to pre-program mock responses so the crawler "visits"
    a small simulated site graph and we can assert on what it discovered.
    """

    SEED_URL = "http://target.com"

    def _make_crawler(self, max_depth: int = 2) -> tuple[Crawler, MagicMock]:
        mock_requester = MagicMock(spec=Requester)
        crawler = Crawler(
            requester=mock_requester,
            max_depth=max_depth,
            scope_guard=ScopeGuard(allowed_domains=["target.com"]),
        )
        return crawler, mock_requester

    def test_crawl_returns_crawl_result(self) -> None:
        crawler, mock_req = self._make_crawler()
        mock_req.get.return_value = (
            _make_mock_response("<html><body></body></html>", url=self.SEED_URL),
            None,
        )
        result = crawler.crawl(self.SEED_URL)
        assert isinstance(result, CrawlResult)

    def test_crawl_records_seed_endpoint(self) -> None:
        crawler, mock_req = self._make_crawler()
        mock_req.get.return_value = (
            _make_mock_response("<html><body></body></html>", url=self.SEED_URL),
            None,
        )
        result = crawler.crawl(self.SEED_URL)
        assert len(result.endpoints) == 1
        assert result.endpoints[0].url == self.SEED_URL

    def test_crawl_follows_links(self) -> None:
        """Crawler should discover and visit /about linked from the seed."""
        crawler, mock_req = self._make_crawler(max_depth=1)

        seed_html = '<html><body><a href="/about">About</a></body></html>'
        about_html = '<html><body><p>About page</p></body></html>'

        def _get_side_effect(url, **kwargs):
            if url == self.SEED_URL:
                return _make_mock_response(seed_html, url=url), None
            if url == "http://target.com/about":
                return _make_mock_response(about_html, url=url), None
            return None, "Not found"

        mock_req.get.side_effect = _get_side_effect
        result = crawler.crawl(self.SEED_URL)

        visited = {ep.url for ep in result.endpoints}
        assert self.SEED_URL in visited
        assert "http://target.com/about" in visited

    def test_crawl_does_not_revisit_urls(self) -> None:
        """Each URL should be fetched at most once even if linked multiple times."""
        crawler, mock_req = self._make_crawler(max_depth=2)

        # Seed links to /page twice
        seed_html = (
            '<html><body>'
            '<a href="/page">Page</a>'
            '<a href="/page">Page again</a>'
            '</body></html>'
        )
        page_html = "<html><body>Content</body></html>"

        def _get_side_effect(url, **kwargs):
            if url == self.SEED_URL:
                return _make_mock_response(seed_html, url=url), None
            if url == "http://target.com/page":
                return _make_mock_response(page_html, url=url), None
            return None, "Not found"

        mock_req.get.side_effect = _get_side_effect
        result = crawler.crawl(self.SEED_URL)

        page_visits = [ep for ep in result.endpoints if ep.url == "http://target.com/page"]
        assert len(page_visits) == 1

    def test_crawl_respects_max_depth(self) -> None:
        """With max_depth=0, only the seed URL should be fetched."""
        crawler, mock_req = self._make_crawler(max_depth=0)

        seed_html = '<html><body><a href="/deep">Deep</a></body></html>'
        mock_req.get.return_value = (
            _make_mock_response(seed_html, url=self.SEED_URL),
            None,
        )

        result = crawler.crawl(self.SEED_URL)
        assert len(result.endpoints) == 1
        assert result.endpoints[0].url == self.SEED_URL

    def test_crawl_records_failed_urls(self) -> None:
        crawler, mock_req = self._make_crawler()
        mock_req.get.return_value = (None, "Connection refused")

        result = crawler.crawl(self.SEED_URL)
        assert self.SEED_URL in result.failed_urls
        assert "Connection refused" in result.failed_urls[self.SEED_URL]

    def test_crawl_blocks_out_of_scope_links(self) -> None:
        """External domain links must not be enqueued."""
        crawler, mock_req = self._make_crawler(max_depth=1)

        seed_html = '<html><body><a href="http://evil.com/attack">Evil</a></body></html>'
        mock_req.get.return_value = (
            _make_mock_response(seed_html, url=self.SEED_URL),
            None,
        )

        result = crawler.crawl(self.SEED_URL)
        visited = {ep.url for ep in result.endpoints}
        assert "http://evil.com/attack" not in visited

    def test_crawl_attaches_forms_to_endpoint(self) -> None:
        crawler, mock_req = self._make_crawler(max_depth=0)
        seed_html = (
            '<html><body>'
            '<form action="/submit" method="POST">'
            '<input name="email" type="email">'
            '</form>'
            '</body></html>'
        )
        mock_req.get.return_value = (
            _make_mock_response(seed_html, url=self.SEED_URL),
            None,
        )

        result = crawler.crawl(self.SEED_URL)
        ep = result.endpoints[0]
        assert len(ep.forms) == 1
        assert ep.forms[0].method == "POST"
        assert ep.forms[0].fields[0].name == "email"

    def test_crawl_attaches_response_headers(self) -> None:
        crawler, mock_req = self._make_crawler(max_depth=0)
        mock_resp = _make_mock_response("<html></html>", url=self.SEED_URL)
        mock_resp.headers = {"Content-Type": "text/html", "X-Frame-Options": "DENY"}
        mock_req.get.return_value = (mock_resp, None)

        result = crawler.crawl(self.SEED_URL)
        ep = result.endpoints[0]
        assert ep.response_headers.get("X-Frame-Options") == "DENY"

    def test_crawl_result_summary_string(self) -> None:
        result = CrawlResult(seed_url="http://target.com")
        summary = result.summary()
        assert "http://target.com" in summary
        assert "endpoints=0" in summary

    def test_crawl_skips_non_html_responses(self) -> None:
        """Non-HTML content (JSON APIs, images) should not be parsed."""
        crawler, mock_req = self._make_crawler(max_depth=0)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"key": "value"}'
        mock_resp.content = b'{"key": "value"}'
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_req.get.return_value = (mock_resp, None)

        result = crawler.crawl(self.SEED_URL)
        # JSON endpoint fetched but not added as an HTML endpoint
        assert len(result.endpoints) == 0
