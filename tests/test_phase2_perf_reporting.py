"""
VortexDAST – tests/test_phase2_perf_reporting.py
────────────────────────────────────────────────────────────────────────────
Tests for Phase 2 performance + reporting additions:
  • core.crawl_cache      — incremental-scan cache
  • core.endpoint_group   — structural endpoint grouping
  • core.issue_tracker    — GitHub / Jira export adapters
  • Reporter.save_pdf     — PDF export
"""

from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crawler import CrawledEndpoint, CrawlResult
from core.parser import FormField, ParsedForm, ParsedLink
from core import crawl_cache
from core.endpoint_group import endpoint_signature, group_endpoints
from core import issue_tracker
from core.reporter import Reporter
from modules.base import Confidence, Finding, Severity


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


def _endpoint(url: str, params=None, forms=None, links=None) -> CrawledEndpoint:
    return CrawledEndpoint(
        url=url,
        status_code=200,
        depth=0,
        forms=forms or [],
        links=links or [],
        query_params=params or {},
        response_headers={"Server": "nginx"},
    )


def _finding(title="XSS", sev=Severity.HIGH) -> Finding:
    return Finding(
        title=title,
        severity=sev,
        confidence=Confidence.FIRM,
        url="https://t.com/p",
        parameter="q",
        description="desc",
        remediation="fix it",
    )


# ─────────────────────────────────────────────────────────────────────────────
# crawl_cache
# ─────────────────────────────────────────────────────────────────────────────


class TestCrawlCache:
    def test_key_deterministic_and_scope_sensitive(self) -> None:
        k1 = crawl_cache.cache_key("https://t.com", {"max_depth": 3})
        k2 = crawl_cache.cache_key("https://t.com", {"max_depth": 3})
        k3 = crawl_cache.cache_key("https://t.com", {"max_depth": 5})
        k4 = crawl_cache.cache_key("https://other.com", {"max_depth": 3})
        assert k1 == k2
        assert k1 != k3
        assert k1 != k4

    def test_key_order_independent(self) -> None:
        a = crawl_cache.cache_key("https://t.com", {"a": 1, "b": [2, 1]})
        b = crawl_cache.cache_key("https://t.com", {"b": [1, 2], "a": 1})
        assert a == b

    def test_round_trip_preserves_attack_surface(self) -> None:
        form = ParsedForm(
            action_url="https://t.com/login",
            method="POST",
            fields=[FormField(name="user", field_type="text", default_value="x")],
        )
        link = ParsedLink(url="https://t.com/next?id=1", query_params={"id": ["1"]})
        result = CrawlResult(
            seed_url="https://t.com",
            endpoints=[_endpoint("https://t.com/p?a=1", {"a": ["1"]}, [form], [link])],
            failed_urls={"https://t.com/bad": "timeout"},
        )
        data = crawl_cache.serialize_crawl_result(result)
        # JSON-safe
        json.dumps(data)
        restored = crawl_cache.deserialize_crawl_result(data)

        assert restored.seed_url == "https://t.com"
        assert len(restored.endpoints) == 1
        ep = restored.endpoints[0]
        assert ep.query_params == {"a": ["1"]}
        assert ep.forms[0].action_url == "https://t.com/login"
        assert ep.forms[0].fields[0].name == "user"
        assert ep.links[0].url == "https://t.com/next?id=1"
        assert restored.failed_urls == {"https://t.com/bad": "timeout"}

    def test_save_and_load_hit(self, tmp_path) -> None:
        path = str(tmp_path / "cache.json")
        key = crawl_cache.cache_key("https://t.com", {"d": 2})
        result = CrawlResult(seed_url="https://t.com", endpoints=[_endpoint("https://t.com/p")])
        crawl_cache.save_cache(path, key, result, now=1000.0)
        loaded = crawl_cache.load_cache(path, key, ttl_seconds=3600, now=1500.0)
        assert loaded is not None
        assert len(loaded.endpoints) == 1

    def test_load_miss_on_key_change(self, tmp_path) -> None:
        path = str(tmp_path / "cache.json")
        crawl_cache.save_cache(path, "KEY-A", CrawlResult(seed_url="x"), now=1000.0)
        assert crawl_cache.load_cache(path, "KEY-B", now=1000.0) is None

    def test_load_miss_on_stale(self, tmp_path) -> None:
        path = str(tmp_path / "cache.json")
        crawl_cache.save_cache(path, "K", CrawlResult(seed_url="x"), now=1000.0)
        assert crawl_cache.load_cache(path, "K", ttl_seconds=100, now=2000.0) is None

    def test_load_miss_on_missing_file(self, tmp_path) -> None:
        assert crawl_cache.load_cache(str(tmp_path / "nope.json"), "K") is None

    def test_load_miss_on_corrupt(self, tmp_path) -> None:
        path = str(tmp_path / "bad.json")
        with open(path, "w") as fh:
            fh.write("{not json")
        assert crawl_cache.load_cache(path, "K") is None


# ─────────────────────────────────────────────────────────────────────────────
# endpoint_group
# ─────────────────────────────────────────────────────────────────────────────


class TestEndpointGroup:
    def test_collapses_value_only_differences(self) -> None:
        eps = [_endpoint(f"https://t.com/item?id={i}", {"id": [str(i)]}) for i in range(5)]
        res = group_endpoints(eps)
        assert res.groups == 1
        assert res.collapsed == 4
        assert len(res.representatives) == 1

    def test_distinct_paths_preserved(self) -> None:
        eps = [
            _endpoint("https://t.com/a?id=1", {"id": ["1"]}),
            _endpoint("https://t.com/b?id=1", {"id": ["1"]}),
        ]
        res = group_endpoints(eps)
        assert res.groups == 2
        assert res.collapsed == 0

    def test_param_name_set_distinguishes(self) -> None:
        eps = [
            _endpoint("https://t.com/s?q=1", {"q": ["1"]}),
            _endpoint("https://t.com/s?q=1&page=2", {"q": ["1"], "page": ["2"]}),
        ]
        res = group_endpoints(eps)
        assert res.groups == 2

    def test_form_signature_distinguishes(self) -> None:
        f1 = ParsedForm("https://t.com/x", "POST", [FormField("a", "text", "")])
        f2 = ParsedForm("https://t.com/x", "POST", [FormField("b", "text", "")])
        eps = [
            _endpoint("https://t.com/p", forms=[f1]),
            _endpoint("https://t.com/p", forms=[f2]),
        ]
        assert group_endpoints(eps).groups == 2

    def test_signature_is_value_independent(self) -> None:
        a = endpoint_signature(_endpoint("https://t.com/p?id=1", {"id": ["1"]}))
        b = endpoint_signature(_endpoint("https://t.com/p?id=999", {"id": ["999"]}))
        assert a == b


# ─────────────────────────────────────────────────────────────────────────────
# issue_tracker
# ─────────────────────────────────────────────────────────────────────────────


class TestIssueTracker:
    def test_fingerprint_stable(self) -> None:
        f = _finding()
        assert issue_tracker.finding_fingerprint(f) == issue_tracker.finding_fingerprint(f)

    def test_filter_min_severity(self) -> None:
        findings = [
            _finding("crit", Severity.CRITICAL),
            _finding("high", Severity.HIGH),
            _finding("med", Severity.MEDIUM),
            _finding("low", Severity.LOW),
        ]
        kept = issue_tracker.filter_by_min_severity(findings, "high")
        titles = {f.title for f in kept}
        assert titles == {"crit", "high"}

    def test_build_github_issue(self) -> None:
        issue = issue_tracker.build_github_issue(_finding())
        assert issue["title"].startswith("[VortexDAST]")
        assert "severity:high" in issue["labels"]
        assert issue_tracker.finding_fingerprint(_finding()) in issue["body"]

    def test_build_jira_issue(self) -> None:
        issue = issue_tracker.build_jira_issue(_finding(), "SEC")
        assert issue["fields"]["project"]["key"] == "SEC"
        assert issue["fields"]["issuetype"]["name"] == "Bug"
        assert "**" not in issue["fields"]["description"]

    def test_create_github_issue_success(self) -> None:
        session = MagicMock()
        # dedup search → none
        session.get.return_value = MagicMock(status_code=200, **{"json.return_value": {"total_count": 0}})
        session.post.return_value = MagicMock(status_code=201, **{"json.return_value": {"number": 42}})
        assert issue_tracker.create_github_issue(session, "o/r", _finding()) == 42

    def test_create_github_issue_dedup_skips(self) -> None:
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=200, **{"json.return_value": {"total_count": 1}})
        assert issue_tracker.create_github_issue(session, "o/r", _finding()) is None
        session.post.assert_not_called()

    def test_create_github_issue_http_error(self) -> None:
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=200, **{"json.return_value": {"total_count": 0}})
        session.post.return_value = MagicMock(status_code=500)
        assert issue_tracker.create_github_issue(session, "o/r", _finding()) is None

    def test_export_to_github_counts(self) -> None:
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=200, **{"json.return_value": {"total_count": 0}})
        session.post.return_value = MagicMock(status_code=201, **{"json.return_value": {"number": 7}})
        findings = [_finding("a", Severity.HIGH), _finding("b", Severity.LOW)]
        res = issue_tracker.export_to_github(session, "o/r", findings, min_severity="high")
        assert res.total_created == 1  # low filtered out
        assert res.created == ["#7"]

    def test_create_jira_issue_success(self) -> None:
        session = MagicMock()
        session.post.return_value = MagicMock(status_code=201, **{"json.return_value": {"key": "SEC-9"}})
        assert issue_tracker.create_jira_issue(session, "https://x.atlassian.net", "SEC", _finding()) == "SEC-9"


# ─────────────────────────────────────────────────────────────────────────────
# PDF export
# ─────────────────────────────────────────────────────────────────────────────


class TestPdfExport:
    def test_save_pdf_writes_valid_file(self, tmp_path) -> None:
        pytest.importorskip("weasyprint")
        path = str(tmp_path / "report.pdf")
        reporter = Reporter([_finding()], "https://t.com", console=MagicMock())
        reporter.save_pdf(path)
        assert os.path.exists(path)
        with open(path, "rb") as fh:
            assert fh.read(5) == b"%PDF-"

    def test_save_dispatch_pdf(self, tmp_path) -> None:
        pytest.importorskip("weasyprint")
        path = str(tmp_path / "out.pdf")
        Reporter([_finding()], "https://t.com", console=MagicMock()).save(path)
        assert os.path.exists(path)


class TestHtmlRepro:
    def test_curl_get(self) -> None:
        from core.reporter import _build_repro_curl
        f = _finding()
        f.url = "https://t.com/p?id=1"
        f.extra = {"method": "GET"}
        cmd = _build_repro_curl(f)
        assert cmd.startswith("curl -sS ")
        assert "https://t.com/p?id=1" in cmd

    def test_curl_post_includes_data(self) -> None:
        from core.reporter import _build_repro_curl
        f = _finding()
        f.extra = {"method": "POST"}
        f.parameter = "user"
        f.payload = "' OR 1=1"
        cmd = _build_repro_curl(f)
        assert "-X POST" in cmd
        assert "--data" in cmd
        assert "user=" in cmd

    def test_html_contains_repro(self) -> None:
        html = Reporter([_finding()], "https://t.com", console=MagicMock())._render_html()
        assert "Reproduce (curl)" in html
        assert "copyRepro" in html
