"""
VortexDAST – tests/test_phase2_grouping.py
Cross-URL finding grouping: payload/query variants, site-wide findings, cookie identity.
"""

from __future__ import annotations

import os
import sys
from typing import Any
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crawler import CrawledEndpoint
from core.reporter import Reporter
from modules.base import Finding, Severity
from modules.headers_audit import HeadersAuditModule


def _f(url: str, **kw: Any) -> Finding:
    kw.setdefault("title", "Reflected XSS")
    kw.setdefault("parameter", "q")
    kw.setdefault("severity", Severity.HIGH)
    kw.setdefault("extra", {"module": "xss_check"})
    return Finding(url=url, **kw)


def test_payload_variants_in_query_merge_into_one_finding() -> None:
    merged = Reporter.deduplicate_findings([
        _f("https://t.com/search?q=%3Cprobe1%3E"),
        _f("https://t.com/search?q=%22probe2"),
        _f("https://t.com/search?q=x&page=2"),
    ])
    assert len(merged) == 1
    assert merged[0].extra["merged_count"] == 3
    assert len(merged[0].extra["affected_urls"]) == 3


def test_same_param_on_different_paths_stays_separate() -> None:
    merged = Reporter.deduplicate_findings([_f("https://t.com/search?q=1"), _f("https://t.com/profile?q=1")])
    assert len(merged) == 2


def test_same_path_on_different_origins_stays_separate() -> None:
    merged = Reporter.deduplicate_findings([_f("https://a.t.com/s?q=1"), _f("https://b.t.com/s?q=1")])
    assert len(merged) == 2


def test_origin_scoped_findings_collapse_across_pages() -> None:
    extra = {"module": "csrf_check", "dedup_scope": "origin"}
    form = "form[action=https://t.com/login][method=POST]"
    merged = Reporter.deduplicate_findings([
        _f(f"https://t.com/{p}", title="Missing CSRF Token on State-Changing Form", parameter=form, extra=dict(extra))
        for p in ("", "about", "contact")
    ])
    assert len(merged) == 1
    assert merged[0].extra["affected_urls"] == ["https://t.com/", "https://t.com/about", "https://t.com/contact"]


def test_single_finding_has_no_affected_urls() -> None:
    assert "affected_urls" not in Reporter.deduplicate_findings([_f("https://t.com/s?q=1")])[0].extra


def _cookie_endpoint(url: str, cookies: str) -> CrawledEndpoint:
    return CrawledEndpoint(url=url, status_code=200, depth=0, response_headers={"Set-Cookie": cookies})


def test_distinct_cookies_on_same_page_are_not_merged() -> None:
    mod = HeadersAuditModule(MagicMock())
    findings = mod.run(_cookie_endpoint("https://t.com/", "session=abc; Secure; SameSite=Lax\ntrack=1; Secure; SameSite=Lax"))
    httponly = [f for f in Reporter.deduplicate_findings(findings) if f.title == "Cookie Missing HttpOnly Flag"]
    assert sorted(f.parameter for f in httponly) == ["session", "track"]


def test_same_cookie_across_pages_reported_once() -> None:
    mod = HeadersAuditModule(MagicMock())
    findings = []
    for path in ("", "a", "b"):
        findings += mod.run(_cookie_endpoint(f"https://t.com/{path}", "session=abc; Secure; SameSite=Lax"))
    httponly = [f for f in Reporter.deduplicate_findings(findings) if f.title == "Cookie Missing HttpOnly Flag"]
    assert len(httponly) == 1
    assert len(httponly[0].extra["affected_urls"]) == 3


def test_sarif_fingerprint_ignores_payload_in_url() -> None:
    def fp(url: str) -> str:
        rep = Reporter([_f(url)], "https://t.com", console=MagicMock())
        return rep.to_sarif()["runs"][0]["results"][0]["partialFingerprints"]["vortexdast/v1"]

    assert fp("https://t.com/search?q=%3Cprobe1%3E") == fp("https://t.com/search?q=%22probe2")
    assert fp("https://t.com/search?q=1") != fp("https://t.com/profile?q=1")


def test_reports_list_affected_urls() -> None:
    findings = [_f("https://t.com/s?q=1"), _f("https://t.com/s?q=2")]
    rep = Reporter(findings, "https://t.com", console=MagicMock())
    assert "**Affected URLs (2)**" in rep._render_markdown()
    html_out = rep._render_html()
    assert "Affected URLs (2)" in html_out and "https://t.com/s?q=2" in html_out
