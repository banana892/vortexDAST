"""
VortexDAST – tests/test_phase2_ssti.py
────────────────────────────────────────────────────────────────────────────
Unit tests for the Server-Side Template Injection (SSTI) module.

Covers:
  • Confirmed evaluation (computed result reflected) → HIGH / FIRM finding
  • Literal reflection only (not evaluated) → no finding (FP guard)
  • Result already in baseline → no finding
  • GET query params + POST form fields
  • Payload file loading and graceful degradation
  • Dynamic registry discovery
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crawler import CrawledEndpoint
from core.parser import FormField, ParsedForm
from core.requester import Requester
from modules.base import Confidence, Severity
from modules.template_injection import (
    TemplateInjectionModule,
    _SSTI_PROBES_PATH,
)
from scanner import MODULE_REGISTRY


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


def _mock_response(text: str = "<html>OK</html>", status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode("utf-8")
    resp.headers = {}
    resp.cookies = {}
    return resp


def _mock_requester() -> MagicMock:
    req = MagicMock(spec=Requester)
    req.dispatch_concurrent.side_effect = lambda tasks, **kwargs: [t() for t in tasks]
    req.get.return_value = (_mock_response(), None)
    req.post.return_value = (_mock_response(), None)
    return req


def _endpoint(
    url: str = "https://target.com/page",
    query_params: Optional[Dict[str, List[str]]] = None,
) -> CrawledEndpoint:
    return CrawledEndpoint(
        url=url,
        status_code=200,
        depth=0,
        response_headers={},
        query_params=query_params or {},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Metadata & loading
# ─────────────────────────────────────────────────────────────────────────────


class TestLoading:
    def test_metadata(self) -> None:
        mod = TemplateInjectionModule(_mock_requester())
        assert mod.name == "template_injection"
        assert "template" in mod.description.lower()

    def test_loads_real_payload_file(self) -> None:
        mod = TemplateInjectionModule(_mock_requester(), payloads_path=_SSTI_PROBES_PATH)
        assert len(mod._probes) >= 4
        for p in mod._probes:
            assert p["value"] and p["expected"]

    def test_missing_payload_handled(self) -> None:
        mod = TemplateInjectionModule(
            _mock_requester(), payloads_path="/nonexistent/ssti.json"
        )
        assert mod._probes == []
        assert mod.run(_endpoint(query_params={"q": ["x"]})) == []

    def test_registered_in_registry(self) -> None:
        assert "template_injection" in MODULE_REGISTRY
        assert MODULE_REGISTRY["template_injection"] is TemplateInjectionModule


# ─────────────────────────────────────────────────────────────────────────────
# GET detection
# ─────────────────────────────────────────────────────────────────────────────


class TestGetDetection:
    def test_confirmed_evaluation_reports_finding(self) -> None:
        """When the computed result is reflected, report HIGH/FIRM."""
        req = _mock_requester()

        def fake_get(url: str, *a, **k):
            # Baseline has no probe; evaluated response echoes the product.
            if "vtxSSTI" in url:
                return (_mock_response("<p>vtxSSTI1337ENDvtx</p>"), None)
            return (_mock_response("<p>clean</p>"), None)

        req.get.side_effect = fake_get
        mod = TemplateInjectionModule(req)

        findings = mod.run(_endpoint(query_params={"name": ["joe"]}))

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.FIRM
        assert f.parameter == "name"
        assert "1337" in f.evidence
        assert f.cvss_score and f.cvss_score >= 9.0

    def test_literal_reflection_is_not_a_finding(self) -> None:
        """Un-evaluated probe echoed verbatim must NOT be reported (FP guard)."""
        req = _mock_requester()

        def fake_get(url: str, *a, **k):
            if "vtxSSTI" in url:
                # Reflect the raw expression unchanged (no evaluation).
                return (_mock_response("<p>vtxSSTI{{191*7}}ENDvtx</p>"), None)
            return (_mock_response("<p>clean</p>"), None)

        req.get.side_effect = fake_get
        mod = TemplateInjectionModule(req)

        findings = mod.run(_endpoint(query_params={"name": ["joe"]}))
        assert findings == []

    def test_result_present_in_baseline_suppressed(self) -> None:
        """If the 'computed' marker is already in the baseline, suppress it."""
        req = _mock_requester()

        def fake_get(url: str, *a, **k):
            return (_mock_response("<p>vtxSSTI1337ENDvtx always here</p>"), None)

        req.get.side_effect = fake_get
        mod = TemplateInjectionModule(req)

        findings = mod.run(_endpoint(query_params={"name": ["joe"]}))
        assert findings == []

    def test_clean_app_no_findings(self) -> None:
        req = _mock_requester()
        req.get.return_value = (_mock_response("<p>nothing reflected</p>"), None)
        mod = TemplateInjectionModule(req)
        findings = mod.run(_endpoint(query_params={"a": ["1"], "b": ["2"]}))
        assert findings == []

    def test_request_error_handled(self) -> None:
        req = _mock_requester()
        req.get.return_value = (None, "timeout")
        mod = TemplateInjectionModule(req)
        findings = mod.run(_endpoint(query_params={"a": ["1"]}))
        assert findings == []


# ─────────────────────────────────────────────────────────────────────────────
# POST detection
# ─────────────────────────────────────────────────────────────────────────────


class TestPostDetection:
    def _form(self) -> ParsedForm:
        return ParsedForm(
            action_url="https://target.com/submit",
            method="POST",
            fields=[FormField(name="comment", field_type="text", default_value="hi")],
        )

    def test_confirmed_evaluation_post(self) -> None:
        req = _mock_requester()

        def fake_post(url: str, data=None, *a, **k):
            val = (data or {}).get("comment", "")
            if "vtxSSTI" in val:
                return (_mock_response("<p>vtxSSTI1337ENDvtx</p>"), None)
            return (_mock_response("<p>clean</p>"), None)

        req.post.side_effect = fake_post
        mod = TemplateInjectionModule(req)

        ep = _endpoint()
        ep.forms = [self._form()]
        findings = mod.run(ep)

        assert len(findings) == 1
        assert findings[0].parameter == "comment"
        assert findings[0].extra["method"] == "POST"

    def test_literal_post_not_reported(self) -> None:
        req = _mock_requester()

        def fake_post(url: str, data=None, *a, **k):
            val = (data or {}).get("comment", "")
            if "vtxSSTI" in val:
                return (_mock_response("<p>vtxSSTI{191*7}ENDvtx</p>"), None)
            return (_mock_response("<p>clean</p>"), None)

        req.post.side_effect = fake_post
        mod = TemplateInjectionModule(req)

        ep = _endpoint()
        ep.forms = [self._form()]
        assert mod.run(ep) == []
