"""
VortexDAST – tests/test_phase2_access_control.py
────────────────────────────────────────────────────────────────────────────
Unit tests for the Broken Access Control module.

Covers:
  • Auth-state detection (cookies / Authorization header / none)
  • Unauthenticated access to a sensitive resource → HIGH / FIRM
  • Correctly-protected resource (401/403, login page, redirect) → no finding
  • Non-sensitive path and no-auth scan → Part 1 skipped
  • IDOR object-reference swap → MEDIUM / TENTATIVE
  • IDOR suppressed when swap yields identical / error / oversized response
  • Role matrix: second identity reaching a sensitive path → HIGH / FIRM
  • Role matrix: second identity fetching the same object reference → HIGH / FIRM
  • Role matrix checks are no-ops when no second identity is configured
  • Payload loading, graceful degradation, registry discovery
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crawler import CrawledEndpoint
from modules.access_control_check import (
    AccessControlCheckModule,
    _ACCESS_CONTROL_PATH,
    _detect_auth,
)
from modules.base import Confidence, Severity
from scanner import MODULE_REGISTRY


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _resp(text: str = "ok", status_code: int = 200, history=None, url: str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.content = text.encode("utf-8")
    r.headers = {}
    r.history = history or []
    r.url = url
    return r


def _requester(
    cookies: Optional[Dict[str, str]] = None,
    auth=None,
    headers: Optional[Dict[str, str]] = None,
) -> MagicMock:
    """A shared (authenticated) requester mock with a configurable session."""
    req = MagicMock()
    req.session.cookies = cookies if cookies is not None else {}
    req.session.auth = auth
    req.session.headers = headers if headers is not None else {"User-Agent": "VortexDAST/1.0"}
    req.session.proxies = {}
    req.timeout = 10
    req.rate_limit_rps = 5.0
    req.verify_ssl = True
    req.max_workers = 10
    return req


def _endpoint(url: str, query_params: Optional[Dict[str, List[str]]] = None) -> CrawledEndpoint:
    return CrawledEndpoint(
        url=url,
        status_code=200,
        depth=0,
        response_headers={},
        query_params=query_params or {},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Loading & auth detection
# ─────────────────────────────────────────────────────────────────────────────


class TestLoadingAndAuth:
    def test_metadata(self) -> None:
        mod = AccessControlCheckModule(_requester())
        assert mod.name == "access_control_check"
        assert "access control" in mod.description.lower()

    def test_loads_real_payload_file(self) -> None:
        mod = AccessControlCheckModule(_requester(), payloads_path=_ACCESS_CONTROL_PATH)
        assert len(mod._sensitive_patterns) >= 5
        assert len(mod._login_indicators) >= 3
        assert "id" in mod._idor_param_names

    def test_missing_payload_handled(self) -> None:
        mod = AccessControlCheckModule(_requester(), payloads_path="/nonexistent.json")
        assert mod._sensitive_patterns == []
        assert mod.run(_endpoint("https://t.com/admin")) == []

    def test_registered(self) -> None:
        assert "access_control_check" in MODULE_REGISTRY
        assert MODULE_REGISTRY["access_control_check"] is AccessControlCheckModule

    def test_detect_auth_cookies(self) -> None:
        assert _detect_auth(_requester(cookies={"sid": "x"})) is True

    def test_detect_auth_header(self) -> None:
        assert _detect_auth(_requester(headers={"Authorization": "Bearer t"})) is True

    def test_detect_auth_none(self) -> None:
        assert _detect_auth(_requester()) is False


# ─────────────────────────────────────────────────────────────────────────────
# Part 1 — unauthenticated access
# ─────────────────────────────────────────────────────────────────────────────


class TestUnauthAccess:
    def _mod_with_unauth(self, shared, unauth) -> AccessControlCheckModule:
        mod = AccessControlCheckModule(shared)
        mod._unauth_requester = unauth  # inject, skip real clone
        return mod

    def test_exposed_sensitive_resource_reported(self) -> None:
        body = "<h1>Admin Dashboard</h1>" + "x" * 500
        shared = _requester(cookies={"sid": "x"})
        shared.get.return_value = (_resp(body, 200), None)
        unauth = MagicMock()
        unauth.get.return_value = (_resp(body, 200), None)

        mod = self._mod_with_unauth(shared, unauth)
        findings = mod.run(_endpoint("https://t.com/admin/users"))

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.FIRM
        assert "Unauthenticated Access" in f.title
        assert f.cvss_score and f.cvss_score >= 8.0

    def test_protected_403_not_reported(self) -> None:
        shared = _requester(cookies={"sid": "x"})
        shared.get.return_value = (_resp("admin page", 200), None)
        unauth = MagicMock()
        unauth.get.return_value = (_resp("Forbidden", 403), None)

        mod = self._mod_with_unauth(shared, unauth)
        assert mod.run(_endpoint("https://t.com/admin")) == []

    def test_login_page_not_reported(self) -> None:
        shared = _requester(cookies={"sid": "x"})
        shared.get.return_value = (_resp("admin page content here", 200), None)
        unauth = MagicMock()
        unauth.get.return_value = (
            _resp('<form>Please sign in <input type="password"></form>', 200),
            None,
        )
        mod = self._mod_with_unauth(shared, unauth)
        assert mod.run(_endpoint("https://t.com/account")) == []

    def test_redirect_to_login_not_reported(self) -> None:
        shared = _requester(cookies={"sid": "x"})
        shared.get.return_value = (_resp("dashboard", 200), None)
        unauth = MagicMock()
        unauth.get.return_value = (
            _resp("home", 200, history=[object()], url="https://t.com/login"),
            None,
        )
        mod = self._mod_with_unauth(shared, unauth)
        assert mod.run(_endpoint("https://t.com/dashboard")) == []

    def test_non_sensitive_path_skipped(self) -> None:
        shared = _requester(cookies={"sid": "x"})
        shared.get.return_value = (_resp("public", 200), None)
        unauth = MagicMock()
        unauth.get.return_value = (_resp("public", 200), None)
        mod = self._mod_with_unauth(shared, unauth)
        # /blog is not a sensitive path → no unauth check
        assert mod.run(_endpoint("https://t.com/blog/post-1")) == []

    def test_no_auth_configured_skips_part1(self) -> None:
        shared = _requester()  # no cookies/auth
        shared.get.return_value = (_resp("admin", 200), None)
        mod = AccessControlCheckModule(shared)
        assert mod._auth_configured is False
        assert mod.run(_endpoint("https://t.com/admin")) == []

    def test_dedup_same_path_once(self) -> None:
        body = "admin" + "y" * 400
        shared = _requester(cookies={"sid": "x"})
        shared.get.return_value = (_resp(body, 200), None)
        unauth = MagicMock()
        unauth.get.return_value = (_resp(body, 200), None)
        mod = self._mod_with_unauth(shared, unauth)

        mod.run(_endpoint("https://t.com/admin/users"))
        calls_after_first = unauth.get.call_count
        mod.run(_endpoint("https://t.com/admin/users"))  # same origin+path
        assert unauth.get.call_count == calls_after_first


# ─────────────────────────────────────────────────────────────────────────────
# Part 2 — IDOR
# ─────────────────────────────────────────────────────────────────────────────


class TestIDOR:
    def test_idor_swap_reported(self) -> None:
        shared = _requester(cookies={"sid": "x"})  # IDOR needs a session
        base = "Invoice #5 total $100 " + "a" * 100
        other = "Invoice #6 total $250 " + "b" * 100

        def fake_get(url: str, *a, **k):
            if "id=6" in url:
                return (_resp(other, 200), None)
            return (_resp(base, 200), None)

        shared.get.side_effect = fake_get
        mod = AccessControlCheckModule(shared)
        findings = mod.run(_endpoint("https://t.com/view", {"id": ["5"]}))

        idor = [f for f in findings if f.confidence == Confidence.TENTATIVE]
        assert len(idor) == 1
        assert idor[0].severity == Severity.MEDIUM
        assert idor[0].parameter == "id"
        assert "IDOR" in idor[0].title

    def test_idor_not_run_without_auth(self) -> None:
        # Unauthenticated: a differing public record must NOT be flagged (no
        # access-control boundary exists to violate).
        shared = _requester()  # no cookies/auth
        base = "Invoice #5 total $100 " + "a" * 100
        other = "Invoice #6 total $250 " + "b" * 100

        def fake_get(url: str, *a, **k):
            return (_resp(other if "id=6" in url else base, 200), None)

        shared.get.side_effect = fake_get
        mod = AccessControlCheckModule(shared)
        assert mod._auth_configured is False
        findings = mod.run(_endpoint("https://t.com/view", {"id": ["5"]}))
        assert [f for f in findings if f.confidence == Confidence.TENTATIVE] == []

    def test_idor_identical_response_not_reported(self) -> None:
        shared = _requester(cookies={"sid": "x"})
        shared.get.return_value = (_resp("same record for every id", 200), None)
        mod = AccessControlCheckModule(shared)
        findings = mod.run(_endpoint("https://t.com/view", {"id": ["5"]}))
        assert [f for f in findings if f.confidence == Confidence.TENTATIVE] == []

    def test_idor_error_on_swap_not_reported(self) -> None:
        shared = _requester(cookies={"sid": "x"})

        def fake_get(url: str, *a, **k):
            if "id=5" in url:
                return (_resp("record 5 content here", 200), None)
            return (_resp("Not Found", 404), None)

        shared.get.side_effect = fake_get
        mod = AccessControlCheckModule(shared)
        findings = mod.run(_endpoint("https://t.com/view", {"id": ["5"]}))
        assert [f for f in findings if f.confidence == Confidence.TENTATIVE] == []

    def test_non_numeric_param_skipped(self) -> None:
        shared = _requester(cookies={"sid": "x"})
        shared.get.return_value = (_resp("x", 200), None)
        mod = AccessControlCheckModule(shared)
        findings = mod.run(_endpoint("https://t.com/view", {"name": ["bob"]}))
        assert findings == []

    def test_numeric_navigation_param_not_treated_as_object_ref(self) -> None:
        # A numeric but navigational param (?page=2) must not be swap-tested,
        # even authenticated, so public pagination is not flagged as IDOR.
        shared = _requester(cookies={"sid": "x"})
        base = "page one " + "a" * 100
        other = "page two " + "b" * 100

        def fake_get(url: str, *a, **k):
            return (_resp(other if "page=2" in url else base, 200), None)

        shared.get.side_effect = fake_get
        mod = AccessControlCheckModule(shared)
        findings = mod.run(_endpoint("https://t.com/blog", {"page": ["1"]}))
        assert [f for f in findings if f.confidence == Confidence.TENTATIVE] == []


# ─────────────────────────────────────────────────────────────────────────────
# Part 3 — role matrix (second identity)
# ─────────────────────────────────────────────────────────────────────────────


class TestRoleMatrix:
    def test_second_identity_reaches_sensitive_path_reported(self) -> None:
        body = "<h1>Admin Dashboard</h1>" + "x" * 500
        shared = _requester(cookies={"sid": "primary"})
        shared.get.return_value = (_resp(body, 200), None)
        role = MagicMock()
        role.get.return_value = (_resp(body, 200), None)

        mod = AccessControlCheckModule(shared)
        mod.set_role_requester(role)
        findings = mod.run(_endpoint("https://t.com/admin/users"))

        hits = [f for f in findings if "Second Identity Reaches" in f.title]
        assert len(hits) == 1
        assert hits[0].severity == Severity.HIGH
        assert hits[0].confidence == Confidence.FIRM

    def test_second_identity_denied_not_reported(self) -> None:
        shared = _requester(cookies={"sid": "primary"})
        shared.get.return_value = (_resp("admin page", 200), None)
        role = MagicMock()
        role.get.return_value = (_resp("Forbidden", 403), None)

        mod = AccessControlCheckModule(shared)
        mod.set_role_requester(role)
        findings = mod.run(_endpoint("https://t.com/admin"))
        assert [f for f in findings if "Second Identity Reaches" in f.title] == []

    def test_role_idor_same_object_reported(self) -> None:
        shared = _requester(cookies={"sid": "primary"})
        body = "Invoice #5 total $100 " + "a" * 100
        shared.get.return_value = (_resp(body, 200), None)
        role = MagicMock()
        role.get.return_value = (_resp(body, 200), None)

        mod = AccessControlCheckModule(shared)
        mod.set_role_requester(role)
        findings = mod.run(_endpoint("https://t.com/view", {"id": ["5"]}))

        hits = [f for f in findings if "Second Identity Accessed Same Object" in f.title]
        assert len(hits) == 1
        assert hits[0].severity == Severity.HIGH
        assert hits[0].confidence == Confidence.FIRM
        assert hits[0].parameter == "id"

    def test_role_idor_denied_not_reported(self) -> None:
        shared = _requester(cookies={"sid": "primary"})
        shared.get.return_value = (_resp("Invoice #5 total $100 " + "a" * 100, 200), None)
        role = MagicMock()
        role.get.return_value = (_resp("Please sign in", 403), None)

        mod = AccessControlCheckModule(shared)
        mod.set_role_requester(role)
        findings = mod.run(_endpoint("https://t.com/view", {"id": ["5"]}))
        assert [f for f in findings if "Second Identity Accessed Same Object" in f.title] == []

    def test_no_role_requester_configured_is_noop(self) -> None:
        shared = _requester(cookies={"sid": "primary"})
        shared.get.return_value = (_resp("<h1>Admin Dashboard</h1>" + "x" * 500, 200), None)
        mod = AccessControlCheckModule(shared)
        # No set_role_requester() call — Part 3 must not run at all.
        findings = mod.run(_endpoint("https://t.com/admin", {"id": ["5"]}))
        assert all(
            "Second Identity" not in f.title for f in findings
        )
