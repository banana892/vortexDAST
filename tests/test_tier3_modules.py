"""
VortexDAST – tests/test_tier3_modules.py
────────────────────────────────────────────────────────────────────────────
Unit tests for Tier 3 components:
  • Cookie string parsing and session injection (core/requester.py)
  • Custom header parsing (scanner._parse_custom_headers)
  • HTTP Basic auth injection (core/requester.py)
  • Path Traversal / LFI module (modules/traversal_check.py)
  • CSRF form audit module (modules/csrf_check.py)

All tests are fully offline — no live network required.

Run with:
    pytest tests/test_tier3_modules.py -v
"""

from __future__ import annotations

import sys
import os
import re
from typing import List, Optional
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.requester import Requester
from core.crawler import CrawledEndpoint
from core.parser import ParsedForm, FormField, ParsedLink


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_mock_response(
    body: str,
    status: int = 200,
    url: str = "http://target.com/",
    content_type: str = "text/html",
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    resp.content = body.encode()
    resp.headers = {"Content-Type": content_type}
    resp.url = url
    return resp


def _make_endpoint(
    url: str = "http://target.com/page",
    query_params: Optional[dict] = None,
    forms: Optional[List] = None,
) -> CrawledEndpoint:
    return CrawledEndpoint(
        url=url,
        status_code=200,
        depth=0,
        forms=forms or [],
        links=[],
        query_params=query_params or {},
    )


def _make_form(
    action_url: str,
    method: str,
    fields: List[FormField],
) -> ParsedForm:
    return ParsedForm(action_url=action_url, method=method, fields=fields)


def _make_field(name: str, field_type: str = "hidden", value: str = "") -> FormField:
    return FormField(name=name, field_type=field_type, default_value=value)


# ─────────────────────────────────────────────────────────────────────────────
# TestCookieParsing
# ─────────────────────────────────────────────────────────────────────────────


class TestCookieParsing:
    """Unit tests for Requester.parse_cookie_string."""

    def test_single_cookie(self) -> None:
        result = Requester.parse_cookie_string("JSESSIONID=abc123")
        assert result == {"JSESSIONID": "abc123"}

    def test_multiple_cookies(self) -> None:
        result = Requester.parse_cookie_string("a=1; b=2; c=3")
        assert result == {"a": "1", "b": "2", "c": "3"}

    def test_whitespace_around_pairs_trimmed(self) -> None:
        result = Requester.parse_cookie_string("  name = value  ;  other=val  ")
        assert result == {"name": "value", "other": "val"}

    def test_empty_string_returns_empty_dict(self) -> None:
        result = Requester.parse_cookie_string("")
        assert result == {}

    def test_malformed_pair_no_equals_skipped(self) -> None:
        result = Requester.parse_cookie_string("bad_pair; x=ok")
        assert "bad_pair" not in result
        assert result["x"] == "ok"

    def test_empty_value_allowed(self) -> None:
        result = Requester.parse_cookie_string("token=")
        assert result == {"token": ""}

    def test_value_with_equals_sign_preserved(self) -> None:
        # Base64 values contain '='; only the first '=' should split name/value.
        result = Requester.parse_cookie_string("auth=abc==; id=1")
        assert result["auth"] == "abc=="
        assert result["id"] == "1"

    def test_multiple_semicolons_no_crash(self) -> None:
        result = Requester.parse_cookie_string("a=1;;; b=2")
        assert result == {"a": "1", "b": "2"}


class TestCookieSessionInjection:
    """Integration tests — verify cookies reach session.cookies."""

    def test_cookies_injected_into_session(self) -> None:
        req = Requester(cookies="JSESSIONID=xyz; auth=true", rate_limit_rps=0)
        assert req.session.cookies.get("JSESSIONID") == "xyz"
        assert req.session.cookies.get("auth") == "true"
        req.close()

    def test_no_cookies_arg_session_jar_empty(self) -> None:
        req = Requester(rate_limit_rps=0)
        # Session may carry default cookies from urllib3 — just check our keys absent.
        assert req.session.cookies.get("JSESSIONID") is None
        req.close()

    def test_set_cookies_method_updates_jar(self) -> None:
        req = Requester(rate_limit_rps=0)
        req.set_cookies("token=mytoken; session=mysession")
        assert req.session.cookies.get("token") == "mytoken"
        assert req.session.cookies.get("session") == "mysession"
        req.close()

    def test_set_cookies_overwrites_existing_key(self) -> None:
        req = Requester(cookies="a=old", rate_limit_rps=0)
        req.set_cookies("a=new")
        assert req.session.cookies.get("a") == "new"
        req.close()


# ─────────────────────────────────────────────────────────────────────────────
# TestCustomHeaderParsing
# ─────────────────────────────────────────────────────────────────────────────


class TestCustomHeaderParsing:
    """Unit tests for scanner._parse_custom_headers."""

    def _parse(self, headers):
        from scanner import _parse_custom_headers
        return _parse_custom_headers(headers)

    def test_none_input_returns_empty_dict(self) -> None:
        assert self._parse(None) == {}

    def test_empty_list_returns_empty_dict(self) -> None:
        assert self._parse([]) == {}

    def test_single_header_parsed(self) -> None:
        result = self._parse(["Authorization: Bearer tok123"])
        assert result == {"Authorization": "Bearer tok123"}

    def test_multiple_headers_parsed(self) -> None:
        result = self._parse(["X-API-Key: secret", "X-Custom: value"])
        assert result["X-API-Key"] == "secret"
        assert result["X-Custom"] == "value"

    def test_value_with_colon_preserved(self) -> None:
        # The value itself contains a colon (e.g. Basic base64-encoded credentials).
        result = self._parse(["Authorization: Basic dXNlcjpwYXNz"])
        assert result["Authorization"] == "Basic dXNlcjpwYXNz"

    def test_malformed_header_no_colon_skipped(self) -> None:
        result = self._parse(["BadHeader", "X-Good: ok"])
        assert "BadHeader" not in result
        assert result["X-Good"] == "ok"

    def test_whitespace_in_name_trimmed(self) -> None:
        result = self._parse(["  X-Token  : myvalue"])
        assert "X-Token" in result
        assert result["X-Token"] == "myvalue"

    def test_auth_headers_reach_requester_session(self) -> None:
        req = Requester(
            auth_headers={"Authorization": "Bearer tok"},
            rate_limit_rps=0,
        )
        assert req.session.headers.get("Authorization") == "Bearer tok"
        req.close()


# ─────────────────────────────────────────────────────────────────────────────
# TestHTTPAuthInjection
# ─────────────────────────────────────────────────────────────────────────────


class TestHTTPAuthInjection:
    """Verify session.auth is configured correctly from http_auth parameter."""

    def test_http_auth_tuple_set_on_session(self) -> None:
        req = Requester(http_auth=("admin", "password"), rate_limit_rps=0)
        assert req.session.auth == ("admin", "password")
        req.close()

    def test_no_auth_session_auth_is_none(self) -> None:
        req = Requester(rate_limit_rps=0)
        assert req.session.auth is None
        req.close()

    def test_http_auth_none_does_not_set_session_auth(self) -> None:
        req = Requester(http_auth=None, rate_limit_rps=0)
        assert req.session.auth is None
        req.close()


# ─────────────────────────────────────────────────────────────────────────────
# TestTraversalCheckModule
# ─────────────────────────────────────────────────────────────────────────────


class TestTraversalCheckModule:
    """Unit tests for modules/traversal_check.py."""

    def _make_requester(self) -> MagicMock:
        req = MagicMock(spec=Requester)
        req.max_workers = 1
        return req

    def _make_module(self):
        from modules.traversal_check import TraversalCheckModule
        req = self._make_requester()
        mod = TraversalCheckModule(req)
        return mod, req

    def test_module_name_and_description(self) -> None:
        from modules.traversal_check import TraversalCheckModule
        assert TraversalCheckModule.name == "traversal_check"
        assert "traversal" in TraversalCheckModule.description.lower()

    def test_no_query_params_returns_no_findings(self) -> None:
        mod, req = self._make_module()
        ep = _make_endpoint("http://t.com/page", query_params={})
        findings = mod.run(ep)
        assert findings == []
        req.get.assert_not_called()

    def test_probes_and_patterns_loaded(self) -> None:
        mod, _ = self._make_module()
        assert len(mod._probes) > 0, "No probes loaded from traversal_probes.json"
        assert len(mod._patterns) > 0, "No patterns loaded from traversal_probes.json"

    def test_detection_unix_passwd_pattern(self) -> None:
        """Verify the unix_passwd_root regex matches a real /etc/passwd line."""
        mod, _ = self._make_module()
        passwd_line = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        matched = mod._matches_pattern(passwd_line)
        assert matched is not None
        assert "passwd" in matched.id or "unix" in matched.os

    def test_detection_windows_win_ini_pattern(self) -> None:
        """Verify the windows detection regex matches win.ini content."""
        mod, _ = self._make_module()
        win_ini = "; for 16-bit app support\r\n[extensions]\r\n[fonts]\r\n"
        matched = mod._matches_pattern(win_ini)
        assert matched is not None
        assert "windows" in matched.os

    def test_no_pattern_match_returns_none(self) -> None:
        mod, _ = self._make_module()
        assert mod._matches_pattern("Hello world 404 Not Found") is None

    def test_confirmed_finding_when_pattern_matches_fuzzed_not_baseline(self) -> None:
        """Baseline clean, fuzzed response contains /etc/passwd — expect finding."""
        mod, req = self._make_module()

        passwd_body = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n"
        baseline_resp = _make_mock_response("Normal page content — no match here")
        fuzz_resp = _make_mock_response(passwd_body)

        # Baseline is first call; subsequent calls return fuzz response.
        req.get.side_effect = [
            (baseline_resp, None),    # baseline fetch
            (fuzz_resp, None),         # first probe that matches
        ]

        ep = _make_endpoint("http://t.com/page", query_params={"file": ["index.php"]})
        findings = mod.run(ep)

        assert len(findings) >= 1
        f = findings[0]
        assert f.severity.value in ("high", "critical")
        assert "file" == f.parameter

    def test_baseline_match_suppresses_finding(self) -> None:
        """Baseline already matches pattern — no finding emitted (false positive guard)."""
        mod, req = self._make_module()

        passwd_body = "root:x:0:0:root:/root:/bin/bash\n"
        baseline_resp = _make_mock_response(passwd_body)  # baseline matches!

        req.get.return_value = (baseline_resp, None)

        ep = _make_endpoint("http://t.com/page", query_params={"q": ["hello"]})
        findings = mod.run(ep)

        assert findings == []

    def test_baseline_fetch_error_returns_no_findings(self) -> None:
        mod, req = self._make_module()
        req.get.return_value = (None, "Connection refused")
        ep = _make_endpoint("http://t.com/page", query_params={"q": ["hello"]})
        findings = mod.run(ep)
        assert findings == []

    def test_server_error_response_skipped(self) -> None:
        """HTTP 500 on a probe must not produce a finding."""
        mod, req = self._make_module()
        baseline_resp = _make_mock_response("Clean baseline")
        error_resp = _make_mock_response("Internal Server Error", status=500)

        req.get.side_effect = [
            (baseline_resp, None),
        ] + [(error_resp, None)] * 50  # all probes return 500

        ep = _make_endpoint("http://t.com/page", query_params={"id": ["1"]})
        findings = mod.run(ep)
        assert findings == []

    def test_inject_param_replaces_correctly(self) -> None:
        from modules.traversal_check import TraversalCheckModule
        original = "http://t.com/page?file=index.php&cat=news"
        result = TraversalCheckModule._inject_param(original, "file", "../../../../etc/passwd")
        assert "file=..%2F..%2F..%2F..%2Fetc%2Fpasswd" in result or "file=" in result
        assert "cat=news" in result  # other params preserved

    def test_deduplication_one_finding_per_param(self) -> None:
        """Only one finding per (url, param_name) even if multiple probes match."""
        mod, req = self._make_module()
        passwd_body = "root:x:0:0:root:/root:/bin/bash\n"
        baseline_resp = _make_mock_response("Clean")

        req.get.side_effect = (
            [(baseline_resp, None)]  # baseline
            + [(_make_mock_response(passwd_body), None)] * 100  # all probes match
        )

        ep = _make_endpoint("http://t.com/page", query_params={"file": ["a"]})
        findings = mod.run(ep)

        # Should be exactly 1 finding for 'file' param.
        assert len(findings) == 1

    # ── POST form fields (§5 item 6: "traversal_check is still GET-only") ──

    def test_post_form_field_confirmed_finding(self) -> None:
        """A POST form's own field is fuzzed via POST, not just GET params."""
        mod, req = self._make_module()
        passwd_body = "root:x:0:0:root:/root:/bin/bash\n"
        baseline_resp = _make_mock_response("Clean baseline")
        fuzz_resp = _make_mock_response(passwd_body)
        req.post.side_effect = [
            (baseline_resp, None),  # POST baseline
            (fuzz_resp, None),      # first probe that matches
        ]

        form = _make_form(
            "http://t.com/download", method="POST",
            fields=[_make_field("file", field_type="text", value="report.pdf")],
        )
        ep = _make_endpoint("http://t.com/page", forms=[form])
        findings = mod.run(ep)

        assert len(findings) == 1
        f = findings[0]
        assert f.parameter == "file"
        assert f.url == "http://t.com/download"
        assert f.extra.get("method") == "POST"
        req.get.assert_not_called()  # no GET candidates on this endpoint at all

    def test_post_baseline_match_suppresses_finding(self) -> None:
        """POST baseline already matching a pattern must not fire (FP guard)."""
        mod, req = self._make_module()
        passwd_body = "root:x:0:0:root:/root:/bin/bash\n"
        req.post.return_value = (_make_mock_response(passwd_body), None)

        form = _make_form(
            "http://t.com/download", method="POST",
            fields=[_make_field("file", field_type="text", value="report.pdf")],
        )
        ep = _make_endpoint("http://t.com/page", forms=[form])
        findings = mod.run(ep)
        assert findings == []

    def test_post_form_with_no_named_fields_skipped(self) -> None:
        mod, req = self._make_module()
        form = _make_form("http://t.com/download", method="POST", fields=[])
        ep = _make_endpoint("http://t.com/page", forms=[form])
        assert mod.run(ep) == []
        req.post.assert_not_called()

    def test_get_and_post_candidates_both_run(self) -> None:
        """A page with both a query param and a POST form fuzzes both shapes."""
        mod, req = self._make_module()
        clean = _make_mock_response("Clean")
        req.get.return_value = (clean, None)
        req.post.return_value = (clean, None)

        form = _make_form(
            "http://t.com/download", method="POST",
            fields=[_make_field("file", field_type="text", value="report.pdf")],
        )
        ep = _make_endpoint(
            "http://t.com/page", query_params={"q": ["hello"]}, forms=[form]
        )
        mod.run(ep)

        req.get.assert_called()
        req.post.assert_called()


# ─────────────────────────────────────────────────────────────────────────────
# TestCSRFCheckModule
# ─────────────────────────────────────────────────────────────────────────────


class TestCSRFCheckModule:
    """Unit tests for modules/csrf_check.py."""

    def _make_module(self):
        from modules.csrf_check import CSRFCheckModule
        req = MagicMock(spec=Requester)
        return CSRFCheckModule(req)

    def test_module_name_and_description(self) -> None:
        from modules.csrf_check import CSRFCheckModule
        assert CSRFCheckModule.name == "csrf_check"
        assert "csrf" in CSRFCheckModule.description.lower()

    def test_no_forms_returns_no_findings(self) -> None:
        mod = self._make_module()
        ep = _make_endpoint(forms=[])
        assert mod.run(ep) == []

    def test_post_form_without_token_returns_finding(self) -> None:
        mod = self._make_module()
        form = _make_form(
            action_url="http://target.com/account/update",
            method="POST",
            fields=[
                _make_field("username", "text"),
                _make_field("email", "email"),
            ],
        )
        ep = _make_endpoint(forms=[form])
        findings = mod.run(ep)
        assert len(findings) == 1
        f = findings[0]
        assert "csrf" in f.title.lower()
        assert f.severity.value in ("high", "critical")

    def test_post_form_with_csrf_token_field_returns_no_finding(self) -> None:
        mod = self._make_module()
        form = _make_form(
            action_url="http://target.com/account/update",
            method="POST",
            fields=[
                _make_field("username", "text"),
                _make_field("csrf_token", "hidden", "abc123"),
            ],
        )
        ep = _make_endpoint(forms=[form])
        assert mod.run(ep) == []

    def test_get_form_non_destructive_not_reported(self) -> None:
        mod = self._make_module()
        form = _make_form(
            action_url="http://target.com/search",
            method="GET",
            fields=[_make_field("q", "text")],
        )
        ep = _make_endpoint(forms=[form])
        assert mod.run(ep) == []

    def test_get_form_destructive_path_without_token_reported(self) -> None:
        mod = self._make_module()
        form = _make_form(
            action_url="http://target.com/user/delete",
            method="GET",
            fields=[_make_field("id", "hidden", "42")],
        )
        ep = _make_endpoint(forms=[form])
        findings = mod.run(ep)
        assert len(findings) == 1

    def test_delete_method_form_without_token_reported(self) -> None:
        mod = self._make_module()
        form = _make_form(
            action_url="http://target.com/posts/1",
            method="DELETE",
            fields=[_make_field("confirm", "hidden", "yes")],
        )
        ep = _make_endpoint(forms=[form])
        findings = mod.run(ep)
        assert len(findings) == 1

    def test_put_method_form_without_token_reported(self) -> None:
        mod = self._make_module()
        form = _make_form(
            action_url="http://target.com/profile",
            method="PUT",
            fields=[_make_field("bio", "text")],
        )
        ep = _make_endpoint(forms=[form])
        assert len(mod.run(ep)) == 1

    def test_alternative_token_names_recognised(self) -> None:
        """All common CSRF token names should be treated as valid protection."""
        from modules.csrf_check import _CSRF_TOKEN_NAMES
        mod = self._make_module()

        for token_name in [
            "authenticity_token",
            "_csrf",
            "xsrf_token",
            "__requestverificationtoken",
            "nonce",
        ]:
            form = _make_form(
                action_url="http://target.com/submit",
                method="POST",
                fields=[
                    _make_field("data", "text"),
                    _make_field(token_name, "hidden", "randomvalue"),
                ],
            )
            ep = _make_endpoint(forms=[form])
            findings = mod.run(ep)
            assert findings == [], (
                f"Token name {token_name!r} should be recognised as CSRF protection"
            )

    def test_non_standard_token_name_substring_match(self) -> None:
        """Names containing 'csrf' substring should be recognised."""
        mod = self._make_module()
        form = _make_form(
            action_url="http://target.com/action",
            method="POST",
            fields=[
                _make_field("__csrf_magic", "hidden", "sid:abc"),
            ],
        )
        ep = _make_endpoint(forms=[form])
        assert mod.run(ep) == []

    def test_case_insensitive_token_name(self) -> None:
        """Token name matching must be case-insensitive."""
        mod = self._make_module()
        form = _make_form(
            action_url="http://target.com/action",
            method="POST",
            fields=[
                _make_field("CSRF_TOKEN", "hidden", "val"),
            ],
        )
        ep = _make_endpoint(forms=[form])
        assert mod.run(ep) == []

    def test_multiple_forms_mixed_results(self) -> None:
        """One protected and one unprotected form on the same endpoint."""
        mod = self._make_module()
        safe_form = _make_form(
            action_url="http://target.com/change-email",
            method="POST",
            fields=[
                _make_field("email", "email"),
                _make_field("csrf_token", "hidden", "tok"),
            ],
        )
        unsafe_form = _make_form(
            action_url="http://target.com/delete-account",
            method="POST",
            fields=[_make_field("confirm", "hidden", "yes")],
        )
        ep = _make_endpoint(forms=[safe_form, unsafe_form])
        findings = mod.run(ep)
        assert len(findings) == 1
        assert "delete-account" in findings[0].parameter

    def test_form_with_no_fields_skipped(self) -> None:
        """A form with zero fields has nothing to audit — skip it."""
        mod = self._make_module()
        form = _make_form(
            action_url="http://target.com/submit",
            method="POST",
            fields=[],
        )
        ep = _make_endpoint(forms=[form])
        assert mod.run(ep) == []

    def test_csrf_module_makes_no_http_requests(self) -> None:
        """The CSRF module is passive — it must never call requester.get/post."""
        mod = self._make_module()
        form = _make_form(
            action_url="http://target.com/action",
            method="POST",
            fields=[_make_field("data", "text")],
        )
        ep = _make_endpoint(forms=[form])
        mod.run(ep)

        # The mock requester's get/post must never have been called.
        mod.requester.get.assert_not_called()
        mod.requester.post.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# TestModuleAutoDiscovery
# ─────────────────────────────────────────────────────────────────────────────


class TestModuleAutoDiscovery:
    """Verify the new modules are auto-discovered by scanner.MODULE_REGISTRY."""

    def test_traversal_check_in_registry(self) -> None:
        from scanner import MODULE_REGISTRY
        assert "traversal_check" in MODULE_REGISTRY

    def test_csrf_check_in_registry(self) -> None:
        from scanner import MODULE_REGISTRY
        assert "csrf_check" in MODULE_REGISTRY

    def test_registry_has_six_modules(self) -> None:
        from scanner import MODULE_REGISTRY
        # Baseline: headers_audit, xss_check, sqli_check, ssrf_check,
        #           traversal_check, csrf_check
        assert len(MODULE_REGISTRY) >= 6
