"""
VortexDAST – tests/test_phase2_nosql.py
────────────────────────────────────────────────────────────────────────────
Unit tests for the NoSQL Injection module.

Covers:
  • Error-based detection (new NoSQL error signature) → HIGH / FIRM
  • Pre-existing baseline error → suppressed
  • Operator-injection differential ($ne vs $eq length delta) → MEDIUM / TENTATIVE
  • Differential suppressed when always-true response equals baseline
  • GET params + POST form fields
  • Payload loading / graceful degradation / registry discovery
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
from modules.nosql_check import NoSQLCheckModule, _NOSQL_PROBES_PATH
from scanner import MODULE_REGISTRY


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


class TestLoading:
    def test_metadata(self) -> None:
        mod = NoSQLCheckModule(_mock_requester())
        assert mod.name == "nosql_check"
        assert "nosql" in mod.description.lower()

    def test_loads_real_payload_file(self) -> None:
        mod = NoSQLCheckModule(_mock_requester(), payloads_path=_NOSQL_PROBES_PATH)
        assert len(mod._boundary_probes) >= 1
        assert len(mod._operator_probes) >= 2
        assert len(mod._regex_operator_probes) >= 2
        assert len(mod._compiled_patterns) >= 5

    def test_missing_payload_handled(self) -> None:
        mod = NoSQLCheckModule(_mock_requester(), payloads_path="/nonexistent.json")
        assert mod._boundary_probes == []
        assert mod.run(_endpoint(query_params={"q": ["x"]})) == []

    def test_registered(self) -> None:
        assert "nosql_check" in MODULE_REGISTRY
        assert MODULE_REGISTRY["nosql_check"] is NoSQLCheckModule


class TestErrorBased:
    def test_new_mongo_error_reported(self) -> None:
        req = _mock_requester()

        def fake_get(url: str, *a, **k):
            # Any value-injection probe (contains encoded quote/brace) errors.
            if "%27" in url or "%22" in url or "%7B" in url or "%5C" in url:
                return (_mock_response("<p>MongoError: FailedToParse near ...</p>"), None)
            return (_mock_response("<p>clean listing</p>"), None)

        req.get.side_effect = fake_get
        mod = NoSQLCheckModule(req)
        findings = mod.run(_endpoint(query_params={"user": ["bob"]}))

        error_findings = [f for f in findings if f.confidence == Confidence.FIRM]
        assert len(error_findings) == 1
        f = error_findings[0]
        assert f.severity == Severity.HIGH
        assert f.parameter == "user"
        assert "MongoDB" in f.title
        assert f.cvss_score and f.cvss_score >= 9.0

    def test_preexisting_error_suppressed(self) -> None:
        req = _mock_requester()
        # Baseline AND everything else already contain a Mongo error.
        req.get.return_value = (_mock_response("MongoError always present"), None)
        mod = NoSQLCheckModule(req)
        findings = mod.run(_endpoint(query_params={"user": ["bob"]}))
        assert findings == []

    def test_clean_app_no_findings(self) -> None:
        req = _mock_requester()
        req.get.return_value = (_mock_response("<p>normal</p>"), None)
        mod = NoSQLCheckModule(req)
        assert mod.run(_endpoint(query_params={"user": ["bob"]})) == []

    def test_request_error_handled(self) -> None:
        req = _mock_requester()
        req.get.return_value = (None, "timeout")
        mod = NoSQLCheckModule(req)
        assert mod.run(_endpoint(query_params={"user": ["bob"]})) == []


class TestOperatorDifferential:
    def test_ne_eq_length_delta_reported(self) -> None:
        req = _mock_requester()

        def fake_get(url: str, *a, **k):
            if "%24ne" in url:  # $ne → always true → full dataset
                return (_mock_response("<p>" + "RECORD " * 200 + "</p>"), None)
            if "%24eq" in url:  # $eq → always false → empty
                return (_mock_response("<p>no results</p>"), None)
            return (_mock_response("<p>baseline single record</p>"), None)

        req.get.side_effect = fake_get
        mod = NoSQLCheckModule(req)
        findings = mod.run(_endpoint(query_params={"user": ["bob"]}))

        op_findings = [f for f in findings if f.confidence == Confidence.TENTATIVE]
        assert len(op_findings) == 1
        f = op_findings[0]
        assert f.severity == Severity.MEDIUM
        assert f.parameter == "user"
        assert "Operator" in f.title

    def test_no_delta_not_reported(self) -> None:
        req = _mock_requester()
        # $ne and $eq return identical bodies → no differential.
        req.get.return_value = (_mock_response("<p>same body everywhere</p>"), None)
        mod = NoSQLCheckModule(req)
        findings = mod.run(_endpoint(query_params={"user": ["bob"]}))
        assert [f for f in findings if f.confidence == Confidence.TENTATIVE] == []

    def test_regex_true_false_length_delta_reported(self) -> None:
        req = _mock_requester()

        def fake_get(url: str, *a, **k):
            if "%24regex" in url and "vtxNoSQLvalueThatDoesNotExist" not in url:
                # ^.*$ → always true → full dataset
                return (_mock_response("<p>" + "RECORD " * 200 + "</p>"), None)
            if "%24regex" in url:
                # anchored-literal $regex → always false → empty
                return (_mock_response("<p>no results</p>"), None)
            return (_mock_response("<p>baseline single record</p>"), None)

        req.get.side_effect = fake_get
        mod = NoSQLCheckModule(req)
        findings = mod.run(_endpoint(query_params={"user": ["bob"]}))

        regex_findings = [
            f for f in findings
            if f.confidence == Confidence.TENTATIVE and f.extra.get("true_operator") == "$regex"
        ]
        assert len(regex_findings) == 1
        f = regex_findings[0]
        assert f.severity == Severity.MEDIUM
        assert f.parameter == "user"
        assert "$regex" in f.payload

    def test_regex_pair_missing_handled(self) -> None:
        mod = NoSQLCheckModule(_mock_requester())
        mod._regex_operator_probes = []
        assert mod._regex_operator_pair() == (None, None)


class TestPost:
    def _form(self) -> ParsedForm:
        return ParsedForm(
            action_url="https://target.com/login",
            method="POST",
            fields=[FormField(name="username", field_type="text", default_value="a")],
        )

    def test_post_operator_differential(self) -> None:
        req = _mock_requester()

        def fake_post(url: str, data=None, *a, **k):
            data = data or {}
            if any("$ne" in k for k in data):
                return (_mock_response("<p>" + "X" * 500 + "</p>"), None)
            if any("$eq" in k for k in data):
                return (_mock_response("<p>short</p>"), None)
            return (_mock_response("<p>baseline</p>"), None)

        req.post.side_effect = fake_post
        mod = NoSQLCheckModule(req)
        ep = _endpoint()
        ep.forms = [self._form()]
        findings = mod.run(ep)

        op_findings = [f for f in findings if f.confidence == Confidence.TENTATIVE]
        assert len(op_findings) == 1
        assert op_findings[0].extra["method"] == "POST"
