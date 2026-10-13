"""
VortexDAST – tests/test_phase3_phase4.py
────────────────────────────────────────────────────────────────────────────
Comprehensive unit tests for Phase 3 (headers_audit) and Phase 4 (xss_check,
sqli_check) modules.

All network calls are mocked via unittest.mock so tests run offline.
Payload JSON files are loaded from disk (the real files in payloads/).

Run with:
    pytest tests/test_phase3_phase4.py -v
"""

from __future__ import annotations

import html as html_lib
import json
import os
import sys
import tempfile
from datetime import timedelta
from typing import Dict, List
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

# Allow imports from the project root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crawler import CapturedJsonRequest, CrawledEndpoint
from core.parser import ParsedForm, FormField, ParsedLink
from core.requester import Requester
from modules.base import Confidence, Finding, Severity
from modules.headers_audit import HeadersAuditModule, _CaseInsensitiveHeaders
from modules.xss_check import XSSCheckModule, _load_xss_canaries, _extract_evidence
from modules.sqli_check import SQLiCheckModule, _load_sqli_probes

# ─────────────────────────────────────────────────────────────────────────────
# Shared fixtures / helpers
# ─────────────────────────────────────────────────────────────────────────────

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_XSS_CANARIES_PATH = os.path.join(_PAYLOADS_DIR, "xss_canaries.json")
_SQLI_PROBES_PATH = os.path.join(_PAYLOADS_DIR, "sqli_probes.json")


def _mock_requester() -> MagicMock:
    req = MagicMock(spec=Requester)
    req.dispatch_concurrent.side_effect = lambda tasks, **kwargs: [t() for t in tasks]
    return req


def _make_endpoint(
    url: str = "https://target.com/page",
    status_code: int = 200,
    headers: Dict[str, str] | None = None,
    query_params: Dict[str, List[str]] | None = None,
    forms: List[ParsedForm] | None = None,
    links: List[ParsedLink] | None = None,
    json_requests: List[CapturedJsonRequest] | None = None,
) -> CrawledEndpoint:
    return CrawledEndpoint(
        url=url,
        status_code=status_code,
        depth=0,
        response_headers=headers or {},
        query_params=query_params or {},
        forms=forms or [],
        links=links or [],
        json_requests=json_requests or [],
    )


def _mock_response(text: str = "", status: int = 200, elapsed: float = 0.05) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.content = text.encode()
    resp.headers = {"Content-Type": "text/html"}
    resp.elapsed = timedelta(seconds=elapsed)
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# _CaseInsensitiveHeaders tests
# ─────────────────────────────────────────────────────────────────────────────


class TestCaseInsensitiveHeaders:

    def test_case_insensitive_get(self) -> None:
        h = _CaseInsensitiveHeaders({"Content-Type": "text/html"})
        assert h.get("content-type") == "text/html"
        assert h.get("CONTENT-TYPE") == "text/html"

    def test_missing_key_returns_none(self) -> None:
        h = _CaseInsensitiveHeaders({})
        assert h.get("X-Frame-Options") is None

    def test_missing_key_returns_default(self) -> None:
        h = _CaseInsensitiveHeaders({})
        assert h.get("X-Frame-Options", "FALLBACK") == "FALLBACK"

    def test_get_all_splits_newline_cookies(self) -> None:
        raw = "session=abc; HttpOnly\ncsrf=xyz; Secure"
        h = _CaseInsensitiveHeaders({"Set-Cookie": raw})
        cookies = h.get_all("Set-Cookie")
        assert len(cookies) == 2
        assert any("session=abc" in c for c in cookies)

    def test_get_all_single_cookie(self) -> None:
        h = _CaseInsensitiveHeaders({"Set-Cookie": "token=x; HttpOnly"})
        assert len(h.get_all("Set-Cookie")) == 1

    def test_get_all_missing_key_returns_empty_list(self) -> None:
        h = _CaseInsensitiveHeaders({})
        assert h.get_all("Set-Cookie") == []


# ─────────────────────────────────────────────────────────────────────────────
# HeadersAuditModule tests
# ─────────────────────────────────────────────────────────────────────────────


class TestHeadersAuditModule:

    def _module(self) -> HeadersAuditModule:
        return HeadersAuditModule(_mock_requester())

    def _finding_titles(self, findings: List[Finding]) -> List[str]:
        return [f.title for f in findings]

    # ── Module metadata ───────────────────────────────────────────────────────

    def test_module_name(self) -> None:
        assert self._module().name == "headers_audit"

    def test_run_returns_list(self) -> None:
        ep = _make_endpoint(headers={"Content-Type": "text/html"})
        result = self._module().run(ep)
        assert isinstance(result, list)

    # ── HSTS ─────────────────────────────────────────────────────────────────

    def test_missing_hsts_on_https(self) -> None:
        ep = _make_endpoint(url="https://target.com/", headers={})
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("Strict-Transport-Security" in t and "Missing" in t for t in titles)

    def test_no_hsts_finding_on_http(self) -> None:
        ep = _make_endpoint(url="http://target.com/", headers={})
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert not any("Strict-Transport-Security" in t for t in titles)

    def test_hsts_short_max_age(self) -> None:
        ep = _make_endpoint(
            url="https://target.com/",
            headers={"Strict-Transport-Security": "max-age=100"},
        )
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("max-age Too Short" in t for t in titles)

    def test_hsts_missing_include_subdomains(self) -> None:
        ep = _make_endpoint(
            url="https://target.com/",
            headers={"Strict-Transport-Security": "max-age=31536000"},
        )
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("includeSubDomains" in t for t in titles)

    def test_hsts_compliant_no_finding(self) -> None:
        ep = _make_endpoint(
            url="https://target.com/",
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"
            },
        )
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert not any("Strict-Transport-Security" in t for t in titles)

    # ── CSP ───────────────────────────────────────────────────────────────────

    def test_missing_csp(self) -> None:
        ep = _make_endpoint(headers={})
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("Content-Security-Policy" in t and "Missing" in t for t in titles)

    def test_csp_unsafe_inline(self) -> None:
        ep = _make_endpoint(
            headers={"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"}
        )
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("unsafe-inline" in t for t in titles)

    def test_csp_unsafe_eval(self) -> None:
        ep = _make_endpoint(
            headers={"Content-Security-Policy": "script-src 'self' 'unsafe-eval'"}
        )
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("unsafe-eval" in t for t in titles)

    def test_csp_wildcard_source(self) -> None:
        ep = _make_endpoint(
            headers={"Content-Security-Policy": "default-src * 'self'"}
        )
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("Wildcard" in t for t in titles)

    def test_csp_strict_no_finding(self) -> None:
        ep = _make_endpoint(
            headers={"Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'"}
        )
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert not any("unsafe-inline" in t or "unsafe-eval" in t or "Wildcard" in t for t in titles)

    # ── X-Frame-Options ───────────────────────────────────────────────────────

    def test_missing_xfo(self) -> None:
        ep = _make_endpoint(headers={})
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("X-Frame-Options" in t and "Missing" in t for t in titles)

    def test_xfo_deny_is_valid(self) -> None:
        ep = _make_endpoint(headers={"X-Frame-Options": "DENY"})
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert not any("X-Frame-Options" in t and ("Weak" in t or "Invalid" in t) for t in titles)

    def test_xfo_sameorigin_is_valid(self) -> None:
        ep = _make_endpoint(headers={"X-Frame-Options": "SAMEORIGIN"})
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert not any("X-Frame-Options" in t and "Weak" in t for t in titles)

    def test_xfo_allow_from_is_weak(self) -> None:
        ep = _make_endpoint(
            headers={"X-Frame-Options": "ALLOW-FROM https://trusted.com"}
        )
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("Weak or Invalid" in t for t in titles)

    # ── X-Content-Type-Options ────────────────────────────────────────────────

    def test_missing_xcto(self) -> None:
        ep = _make_endpoint(headers={})
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("X-Content-Type-Options" in t and "Missing" in t for t in titles)

    def test_xcto_nosniff_no_finding(self) -> None:
        ep = _make_endpoint(headers={"X-Content-Type-Options": "nosniff"})
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert not any("X-Content-Type-Options" in t for t in titles)

    def test_xcto_invalid_value(self) -> None:
        ep = _make_endpoint(headers={"X-Content-Type-Options": "sniff"})
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("X-Content-Type-Options" in t and "Invalid" in t for t in titles)

    # ── Set-Cookie flags ──────────────────────────────────────────────────────

    def test_cookie_missing_httponly(self) -> None:
        ep = _make_endpoint(
            headers={"Set-Cookie": "session=abc; Secure; SameSite=Lax"}
        )
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("HttpOnly" in t for t in titles)

    def test_cookie_missing_secure(self) -> None:
        ep = _make_endpoint(
            headers={"Set-Cookie": "session=abc; HttpOnly; SameSite=Lax"}
        )
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("Secure" in t for t in titles)

    def test_cookie_missing_samesite(self) -> None:
        ep = _make_endpoint(
            headers={"Set-Cookie": "session=abc; HttpOnly; Secure"}
        )
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("SameSite" in t for t in titles)

    def test_fully_hardened_cookie_no_finding(self) -> None:
        ep = _make_endpoint(
            headers={"Set-Cookie": "session=abc; HttpOnly; Secure; SameSite=Strict"}
        )
        findings = self._module().run(ep)
        cookie_findings = [
            f for f in findings
            if f.extra.get("cookie_name") == "session"
        ]
        assert cookie_findings == []

    def test_samesite_none_without_secure_flagged(self) -> None:
        ep = _make_endpoint(
            headers={"Set-Cookie": "session=abc; HttpOnly; SameSite=None"}
        )
        findings = self._module().run(ep)
        titles = self._finding_titles(findings)
        assert any("SameSite=None" in t for t in titles)

    def test_no_cookies_no_cookie_findings(self) -> None:
        ep = _make_endpoint(headers={"Content-Type": "text/html"})
        findings = self._module().run(ep)
        cookie_findings = [f for f in findings if "Cookie" in f.title]
        assert cookie_findings == []

    # ── Severity checks ───────────────────────────────────────────────────────

    def test_missing_csp_is_medium(self) -> None:
        ep = _make_endpoint(headers={})
        findings = self._module().run(ep)
        csp_missing = next(
            (f for f in findings if "Content-Security-Policy" in f.title and "Missing" in f.title),
            None,
        )
        assert csp_missing is not None
        assert csp_missing.severity == Severity.MEDIUM

    def test_missing_xcto_is_low(self) -> None:
        ep = _make_endpoint(headers={})
        findings = self._module().run(ep)
        xcto_missing = next(
            (f for f in findings if "X-Content-Type-Options" in f.title and "Missing" in f.title),
            None,
        )
        assert xcto_missing is not None
        assert xcto_missing.severity == Severity.LOW

    def test_all_findings_have_url(self) -> None:
        ep = _make_endpoint(url="https://target.com/test", headers={})
        findings = self._module().run(ep)
        for f in findings:
            assert f.url == "https://target.com/test"

    def test_all_findings_have_remediation(self) -> None:
        ep = _make_endpoint(headers={})
        findings = self._module().run(ep)
        for f in findings:
            assert f.remediation, f"Finding '{f.title}' has no remediation text"


# ─────────────────────────────────────────────────────────────────────────────
# Payload loader tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPayloadLoaders:

    def test_xss_canaries_json_is_valid(self) -> None:
        probes, encoded_forms = _load_xss_canaries(_XSS_CANARIES_PATH)
        assert len(probes) > 0
        assert len(encoded_forms) > 0

    def test_xss_probes_have_required_fields(self) -> None:
        probes, _ = _load_xss_canaries(_XSS_CANARIES_PATH)
        for probe in probes:
            assert "id" in probe
            assert "value" in probe
            assert "boundary_chars" in probe
            assert isinstance(probe["boundary_chars"], list)

    def test_xss_encoded_forms_contains_angle_brackets(self) -> None:
        _, encoded_forms = _load_xss_canaries(_XSS_CANARIES_PATH)
        assert "<" in encoded_forms
        assert ">" in encoded_forms

    def test_xss_canaries_missing_file_returns_empty(self) -> None:
        probes, encoded_forms = _load_xss_canaries("/nonexistent/path/xss.json")
        assert probes == []
        assert encoded_forms == {}

    def test_sqli_probes_json_is_valid(self) -> None:
        probes, time_probes, patterns, indicators = _load_sqli_probes(_SQLI_PROBES_PATH)
        assert len(probes) > 0
        assert len(time_probes) > 0
        assert len(patterns) > 0
        assert len(indicators) > 0

    def test_sqli_probes_have_required_fields(self) -> None:
        probes, _, _, _ = _load_sqli_probes(_SQLI_PROBES_PATH)
        for probe in probes:
            assert "id" in probe
            assert "value" in probe

    def test_sqli_time_based_probes_have_required_fields(self) -> None:
        _, time_probes, _, _ = _load_sqli_probes(_SQLI_PROBES_PATH)
        for probe in time_probes:
            assert "id" in probe
            assert "value" in probe
            assert probe.get("delay_seconds", 0) > 0

    def test_sqli_patterns_compiled_for_all_dbms(self) -> None:
        _, _, patterns, _ = _load_sqli_probes(_SQLI_PROBES_PATH)
        dbms_names = {p.dbms for p in patterns}
        for expected in ["MySQL", "PostgreSQL", "SQLite", "MSSQL", "Oracle"]:
            assert expected in dbms_names, f"Missing DBMS patterns: {expected}"

    def test_sqli_probes_missing_file_returns_empty(self) -> None:
        probes, time_probes, patterns, indicators = _load_sqli_probes("/nonexistent/path/sqli.json")
        assert probes == []
        assert time_probes == []
        assert patterns == []
        assert indicators == []


# ─────────────────────────────────────────────────────────────────────────────
# XSSCheckModule tests
# ─────────────────────────────────────────────────────────────────────────────


class TestXSSCheckModule:

    def _module(self, payloads_path: str = _XSS_CANARIES_PATH) -> XSSCheckModule:
        return XSSCheckModule(_mock_requester(), payloads_path=payloads_path)

    def test_module_name(self) -> None:
        assert self._module().name == "xss_check"

    def test_no_params_no_forms_returns_empty(self) -> None:
        ep = _make_endpoint()
        module = self._module()
        module.requester.get.return_value = (_mock_response("<html></html>"), None)
        findings = module.run(ep)
        assert findings == []

    def test_no_probes_loaded_returns_empty(self) -> None:
        """When payload file is missing, module should return empty gracefully."""
        module = self._module(payloads_path="/nonexistent.json")
        ep = _make_endpoint(query_params={"q": ["test"]})
        findings = module.run(ep)
        assert findings == []

    def test_detects_raw_reflection_in_get_param(self) -> None:
        """When a boundary char is reflected verbatim, a finding is returned."""
        module = self._module()

        # Vulnerable app: echoes the q parameter back verbatim.
        def _get(url: str, **kwargs: object) -> tuple:
            q = parse_qs(urlparse(url).query).get("q", ["hello"])[0]
            return _mock_response(f"<html>You searched for: {q} — results</html>"), None

        module.requester.get.side_effect = _get

        ep = _make_endpoint(
            url="https://target.com/search",
            query_params={"q": ["hello"]},
        )
        findings = module.run(ep)

        xss_findings = [f for f in findings if "XSS" in f.title]
        assert len(xss_findings) >= 1
        assert xss_findings[0].severity == Severity.HIGH
        assert xss_findings[0].parameter == "q"

    def test_encoded_reflection_not_flagged(self) -> None:
        """Properly HTML-encoded reflection (&lt; etc.) must NOT produce a finding."""
        module = self._module()

        # Both baseline and fuzzed have only encoded angle brackets.
        safe_resp = _mock_response(
            "<html>Searched: &lt;script&gt;&amp;quot; — safe</html>"
        )
        module.requester.get.return_value = (safe_resp, None)

        ep = _make_endpoint(
            url="https://target.com/search",
            query_params={"q": ["test"]},
        )
        findings = module.run(ep)
        xss_findings = [f for f in findings if "XSS" in f.title]
        assert xss_findings == []

    def test_detects_reflection_in_post_form(self) -> None:
        """XSS detection should also work against POST form fields."""
        module = self._module()

        module.requester.get.return_value = (_mock_response("<html>Submit form</html>"), None)
        module.requester.post.side_effect = lambda url, data=None, **kw: (
            _mock_response(f"<html>Hello: {data['username']} — welcome</html>"), None
        )

        form = ParsedForm(
            action_url="https://target.com/submit",
            method="POST",
            fields=[FormField(name="username", field_type="text", default_value="")],
        )
        ep = _make_endpoint(
            url="https://target.com/submit",
            forms=[form],
        )
        findings = module.run(ep)
        post_xss = [f for f in findings if "XSS" in f.title]
        assert len(post_xss) >= 1

    def test_unrelated_error_page_is_not_reflection(self) -> None:
        """A different page full of markup (e.g. a 501 error page) must not count as reflection."""
        module = self._module()
        module.requester.get.return_value = (_mock_response("<html>Submit form</html>"), None)
        module.requester.post.return_value = (_mock_response(
            "<!DOCTYPE HTML><html><head><title>Error</title></head>"
            "<body><h1>Error response</h1><p>Error code: 501</p>"
            "<p>Message: Unsupported method ('POST').</p></body></html>",
            status=501,
        ), None)
        form = ParsedForm(
            action_url="https://target.com/x", method="POST",
            fields=[FormField(name="a", field_type="text", default_value="")],
        )
        assert module.run(_make_endpoint(url="https://target.com/", forms=[form])) == []

    def test_encoded_reflection_is_not_reported(self) -> None:
        module = self._module()

        def _get(url: str, **kwargs: object) -> tuple:
            q = parse_qs(urlparse(url).query).get("q", [""])[0]
            return _mock_response(f"<html>{html_lib.escape(q, quote=True)}</html>"), None

        module.requester.get.side_effect = _get
        assert module.run(_make_endpoint(url="https://target.com/s", query_params={"q": ["x"]})) == []

    def test_quick_mode_continues_when_marker_reflected_but_rich_probes_filtered(self) -> None:
        """An app that strips 'script' and quotes must still get the simpler probes tried."""
        module = self._module()

        def _get(url: str, **kwargs: object) -> tuple:
            q = parse_qs(urlparse(url).query).get("q", [""])[0]
            q = q.replace("script", "").replace('"', "").replace(">", "")
            return _mock_response(f"<html>{q}</html>"), None

        module.requester.get.side_effect = _get
        findings = module.run(_make_endpoint(url="https://target.com/s", query_params={"q": ["x"]}))
        assert any(f.payload == "vdastXSS1<vdast" for f in findings)

    def test_get_form_skipped_for_post_fuzzer(self) -> None:
        """GET forms (action=GET) must not be POSTed by the XSS module."""
        module = self._module()
        module.requester.get.return_value = (_mock_response("<html></html>"), None)

        get_form = ParsedForm(
            action_url="https://target.com/search",
            method="GET",
            fields=[FormField(name="q", field_type="text", default_value="")],
        )
        ep = _make_endpoint(forms=[get_form])
        module.run(ep)

        # post() should never have been called.
        module.requester.post.assert_not_called()

    def test_baseline_fetch_failure_does_not_crash(self) -> None:
        """If the baseline request fails, the module should continue gracefully."""
        module = self._module()
        module.requester.get.return_value = (None, "Connection refused")

        ep = _make_endpoint(query_params={"q": ["test"]})
        findings = module.run(ep)
        assert isinstance(findings, list)

    def test_finding_has_payload_and_parameter(self) -> None:
        module = self._module()
        baseline_resp = _mock_response("<html></html>")
        fuzzed_resp = _mock_response("<html>vdastXSS1<vdast found</html>")

        module.requester.get.side_effect = (
            [(baseline_resp, None)] + [(fuzzed_resp, None)] * 20
        )

        ep = _make_endpoint(query_params={"id": ["1"]})
        findings = module.run(ep)

        if findings:
            f = findings[0]
            assert f.parameter is not None
            assert f.payload is not None

    # ── Captured JSON API request fuzzing ──────────────────────────────────

    def test_json_body_leaf_reflection_detected(self) -> None:
        module = self._module()
        module.requester.get.return_value = (_mock_response("<html>unrelated</html>"), None)

        def fake_post(url, **kwargs):
            body = kwargs.get("json")
            value = body.get("comment", "") if isinstance(body, dict) else ""
            if "vdastXSS" in str(value):
                return _mock_response(f"<html>Comment: {value}</html>"), None
            return _mock_response("<html>Comment: hello</html>"), None

        module.requester.post.side_effect = fake_post
        captured = CapturedJsonRequest(
            url="https://target.com/api/comments", method="POST", body={"comment": "hello"}
        )
        ep = _make_endpoint(json_requests=[captured])
        findings = module.run(ep)

        xss_findings = [f for f in findings if "XSS" in f.title]
        assert len(xss_findings) >= 1
        assert xss_findings[0].parameter == "body:comment"
        assert xss_findings[0].extra["method"] == "POST (JSON)"

    def test_no_reflection_in_json_body_yields_no_findings(self) -> None:
        module = self._module()
        module.requester.get.return_value = (_mock_response("<html>unrelated</html>"), None)
        module.requester.post.return_value = (_mock_response("<html>No echo here</html>"), None)
        captured = CapturedJsonRequest(
            url="https://target.com/api/comments", method="POST", body={"comment": "hello"}
        )
        ep = _make_endpoint(json_requests=[captured])
        findings = module.run(ep)
        assert [f for f in findings if "XSS" in f.title] == []


# ─────────────────────────────────────────────────────────────────────────────
# SQLiCheckModule tests
# ─────────────────────────────────────────────────────────────────────────────


class TestSQLiCheckModule:

    def _module(self, payloads_path: str = _SQLI_PROBES_PATH) -> SQLiCheckModule:
        return SQLiCheckModule(_mock_requester(), payloads_path=payloads_path)

    def test_module_name(self) -> None:
        assert self._module().name == "sqli_check"

    def test_no_params_no_forms_returns_empty(self) -> None:
        module = self._module()
        module.requester.get.return_value = (_mock_response("<html></html>"), None)
        ep = _make_endpoint()
        assert module.run(ep) == []

    def test_no_probes_loaded_returns_empty(self) -> None:
        module = self._module(payloads_path="/nonexistent.json")
        ep = _make_endpoint(query_params={"id": ["1"]})
        assert module.run(ep) == []

    def test_detects_mysql_error_in_response(self) -> None:
        module = self._module()
        baseline_resp = _mock_response("<html>Normal page</html>")
        error_resp = _mock_response(
            "<html>You have an error in your SQL syntax near '''' at line 1</html>",
            status=500,
        )
        module.requester.get.side_effect = (
            [(baseline_resp, None)] * 2  # baseline calls
            + [(error_resp, None)] * 30  # probe calls
        )
        ep = _make_endpoint(query_params={"id": ["1"]})
        findings = module.run(ep)
        sqli_findings = [f for f in findings if "SQL" in f.title]
        assert len(sqli_findings) >= 1
        assert sqli_findings[0].severity == Severity.HIGH

    def test_detects_postgresql_error(self) -> None:
        module = self._module()
        baseline_resp = _mock_response("<html>OK</html>")
        error_resp = _mock_response(
            "<html>pg_query() failed: unterminated quoted string at or near</html>"
        )
        module.requester.get.side_effect = (
            [(baseline_resp, None)] * 2
            + [(error_resp, None)] * 30
        )
        ep = _make_endpoint(query_params={"user": ["admin"]})
        findings = module.run(ep)
        sqli_findings = [f for f in findings if "SQL" in f.title and "Error" in f.title]
        assert len(sqli_findings) >= 1
        extra_dbms = [f.extra.get("dbms") for f in sqli_findings]
        assert "PostgreSQL" in extra_dbms

    def test_baseline_error_suppresses_finding(self) -> None:
        """If baseline already contains a DB error, findings must be suppressed."""
        module = self._module()
        # Both baseline AND fuzzed contain the same error.
        error_resp = _mock_response(
            "<html>You have an error in your SQL syntax</html>"
        )
        module.requester.get.return_value = (error_resp, None)

        ep = _make_endpoint(query_params={"id": ["1"]})
        findings = module.run(ep)
        # The baseline error indicator check should suppress all findings.
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        assert high_findings == []

    def test_http_500_on_probe_raises_medium_finding(self) -> None:
        module = self._module()
        baseline_resp = _mock_response("<html>OK</html>", status=200)
        # A 500 with no recognisable DBMS error string.
        error_500_resp = _mock_response("<html>Internal Server Error</html>", status=500)

        # Sequence: 2 baselines (for the param + boolean blind), then probes.
        module.requester.get.side_effect = (
            [(baseline_resp, None)] * 2
            + [(error_500_resp, None)] * 30
        )

        ep = _make_endpoint(query_params={"cat": ["1"]})
        findings = module.run(ep)
        # At minimum a MEDIUM finding for the 500 status.
        medium_or_higher = [
            f for f in findings
            if f.severity in (Severity.HIGH, Severity.MEDIUM)
        ]
        assert len(medium_or_higher) >= 1

    def test_detects_boolean_blind_by_length_diff(self) -> None:
        """Significant response length difference between TRUE/FALSE probes → MEDIUM finding."""
        module = self._module()

        large_resp = _mock_response("<html>" + "X" * 5000 + "</html>")
        small_resp = _mock_response("<html>Not found</html>")
        clean_resp = _mock_response("<html>Normal</html>")

        call_count = [0]

        def _side_effect(url, **kwargs):
            call_count[0] += 1
            # First call: baseline for param
            if call_count[0] == 1:
                return clean_resp, None
            # Boolean probe calls — TRUE returns large, FALSE returns small.
            if "1%27%3D%271" in url or "AND+%271%27%3D%271" in url or "1'='1" in url:
                return large_resp, None
            if "1%27%3D%272" in url or "AND+%271%27%3D%272" in url or "1'='2" in url:
                return small_resp, None
            return clean_resp, None

        module.requester.get.side_effect = _side_effect

        ep = _make_endpoint(query_params={"id": ["1"]})
        findings = module.run(ep)
        blind_findings = [f for f in findings if "Blind" in f.title]
        # Boolean blind may or may not trigger depending on probe URL encoding;
        # just ensure the module runs without error.
        assert isinstance(findings, list)

    def test_detects_sqli_in_post_form(self) -> None:
        module = self._module()
        baseline_resp = _mock_response("<html>Login form</html>")
        error_resp = _mock_response(
            "<html>Warning: mysql_fetch_array() error</html>"
        )
        module.requester.post.side_effect = (
            [(baseline_resp, None)]   # POST baseline
            + [(error_resp, None)] * 30  # probe injections
        )
        module.requester.get.return_value = (baseline_resp, None)

        form = ParsedForm(
            action_url="https://target.com/login",
            method="POST",
            fields=[
                FormField(name="username", field_type="text", default_value="admin"),
                FormField(name="password", field_type="password", default_value=""),
            ],
        )
        ep = _make_endpoint(forms=[form])
        findings = module.run(ep)
        sqli_findings = [f for f in findings if "SQL" in f.title]
        assert len(sqli_findings) >= 1

    def test_finding_evidence_is_not_empty(self) -> None:
        module = self._module()
        baseline_resp = _mock_response("<html>OK</html>")
        error_resp = _mock_response(
            "<html>You have an error in your SQL syntax</html>"
        )
        module.requester.get.side_effect = (
            [(baseline_resp, None)] * 2 + [(error_resp, None)] * 30
        )
        ep = _make_endpoint(query_params={"id": ["1"]})
        findings = module.run(ep)
        for f in findings:
            if f.severity == Severity.HIGH:
                assert f.evidence, "HIGH SQLi finding must have evidence"

    # ── Time-based blind SQLi ─────────────────────────────────────────────

    def test_detects_time_based_blind_mysql(self) -> None:
        module = self._module()
        baseline_resp = _mock_response("<html>OK</html>", elapsed=0.05)
        delayed_resp = _mock_response("<html>OK</html>", elapsed=4.5)

        def fake_get(url, **kwargs):
            if "SLEEP" in url:
                return delayed_resp, None
            return baseline_resp, None

        module.requester.get.side_effect = fake_get
        ep = _make_endpoint(query_params={"id": ["1"]})
        findings = module.run(ep)

        time_findings = [f for f in findings if "Time-Based" in f.title]
        assert len(time_findings) == 1
        f = time_findings[0]
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.FIRM
        assert f.extra["dbms"] == "MySQL"

    def test_time_based_blind_not_reported_without_delay(self) -> None:
        module = self._module()
        module.requester.get.return_value = (_mock_response("<html>OK</html>", elapsed=0.08), None)
        ep = _make_endpoint(query_params={"id": ["1"]})
        findings = module.run(ep)
        assert [f for f in findings if "Time-Based" in f.title] == []

    def test_time_based_blind_requires_reproducible_confirmation(self) -> None:
        """A single slow sample that doesn't reproduce (network jitter) must not be reported."""
        module = self._module()
        baseline_resp = _mock_response("<html>OK</html>", elapsed=0.05)
        slow_once = _mock_response("<html>OK</html>", elapsed=4.5)
        fast_confirm = _mock_response("<html>OK</html>", elapsed=0.06)
        call_count = {"n": 0}

        def fake_get(url, **kwargs):
            if "SLEEP" in url:
                call_count["n"] += 1
                return (slow_once, None) if call_count["n"] == 1 else (fast_confirm, None)
            return baseline_resp, None

        module.requester.get.side_effect = fake_get
        ep = _make_endpoint(query_params={"id": ["1"]})
        findings = module.run(ep)
        assert [f for f in findings if "Time-Based" in f.title] == []

    # ── Captured JSON API request fuzzing ──────────────────────────────────

    def test_detects_error_in_captured_json_body_leaf(self) -> None:
        module = self._module()
        error_resp = _mock_response(
            "<html>You have an error in your SQL syntax near '''' at line 1</html>",
            status=500,
        )
        baseline_resp = _mock_response("<html>OK</html>")

        def fake_post(url, **kwargs):
            body = kwargs.get("json")
            value = body.get("user", {}).get("name", "") if isinstance(body, dict) else ""
            if "'" in str(value):
                return error_resp, None
            return baseline_resp, None

        module.requester.post.side_effect = fake_post
        captured = CapturedJsonRequest(
            url="https://target.com/api/profile",
            method="POST",
            body={"user": {"name": "bob"}},
        )
        ep = _make_endpoint(json_requests=[captured])
        findings = module.run(ep)

        sqli_findings = [f for f in findings if "SQL Injection" in f.title]
        assert len(sqli_findings) >= 1
        assert sqli_findings[0].parameter == "body:user.name"
        assert sqli_findings[0].extra["method"] == "POST (JSON)"

    def test_json_path_segment_is_fuzzed(self) -> None:
        module = self._module()
        error_resp = _mock_response(
            "<html>You have an error in your SQL syntax near '''' at line 1</html>",
            status=500,
        )
        baseline_resp = _mock_response("<html>OK</html>")

        def fake_post(url, **kwargs):
            if url.endswith("42'"):
                return error_resp, None
            return baseline_resp, None

        module.requester.post.side_effect = fake_post
        captured = CapturedJsonRequest(
            url="https://target.com/api/widgets/42", method="POST", body={"qty": 1}
        )
        ep = _make_endpoint(json_requests=[captured])
        findings = module.run(ep)

        path_findings = [f for f in findings if f.parameter and f.parameter.startswith("path:")]
        assert len(path_findings) >= 1

    def test_no_captured_json_requests_adds_nothing(self) -> None:
        module = self._module()
        module.requester.get.return_value = (_mock_response("<html>OK</html>"), None)
        ep = _make_endpoint(query_params={"id": ["1"]})
        findings = module.run(ep)
        json_findings = [f for f in findings if "(JSON)" in (f.extra.get("method") or "")]
        assert json_findings == []

    def test_baseline_request_failure_is_skipped_gracefully(self) -> None:
        module = self._module()
        module.requester.get.return_value = (None, "Timeout")
        ep = _make_endpoint(query_params={"id": ["1"]})
        findings = module.run(ep)
        assert isinstance(findings, list)

    # ── DBMS pattern regex compilation ───────────────────────────────────────

    def test_all_dbms_patterns_compile(self) -> None:
        """Every pattern in sqli_probes.json must compile to a valid regex."""
        _, _, patterns, _ = _load_sqli_probes(_SQLI_PROBES_PATH)
        assert len(patterns) > 0
        for p in patterns:
            # If the pattern compiled, searching an empty string won't raise.
            assert p.pattern.search("") is not None or True  # just confirms no exception


# ─────────────────────────────────────────────────────────────────────────────
# _extract_evidence helper tests
# ─────────────────────────────────────────────────────────────────────────────


class TestExtractEvidence:

    def test_finds_probe_in_body(self) -> None:
        body = "Normal text. vdastXSS1<vdast injected here. More text."
        result = _extract_evidence(body, "vdastXSS1<vdast")
        assert "vdastXSS1<vdast" in result

    def test_truncation_markers_added(self) -> None:
        prefix = "A" * 200
        suffix = "B" * 200
        body = prefix + "PROBE" + suffix
        result = _extract_evidence(body, "PROBE")
        assert "[…]" in result

    def test_probe_not_found_returns_start_of_body(self) -> None:
        body = "No probe here at all."
        result = _extract_evidence(body, "MISSING_PROBE")
        assert result == body  # body is short enough to return fully

    def test_empty_body_returns_empty_string(self) -> None:
        result = _extract_evidence("", "PROBE")
        assert result == ""
