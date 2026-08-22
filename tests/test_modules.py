"""
VortexDAST – tests/test_modules.py
────────────────────────────────────────────────────────────────────────────
Unit tests for modules/base.py (Finding, Severity, BaseScannerModule).

Additional module-specific tests (XSS, SQLi, SSRF, headers) will be added
here as Phases 3 and 4 are implemented.

Run with:
    pytest tests/test_modules.py -v
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import MagicMock
from typing import List

import pytest

from modules.base import BaseScannerModule, Finding, Severity
from core.crawler import CrawledEndpoint
from core.requester import Requester


# ─────────────────────────────────────────────────────────────────────────────
# Concrete test module (implements the abstract interface)
# ─────────────────────────────────────────────────────────────────────────────


class _EchoModule(BaseScannerModule):
    """Test module that echoes a pre-configured list of findings."""

    name = "echo"
    description = "Returns a fixed list of findings for testing."

    def __init__(self, requester: Requester, findings: List[Finding]) -> None:
        super().__init__(requester)
        self._findings = findings

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        return self._findings


def _make_endpoint(url: str = "http://target.com/page") -> CrawledEndpoint:
    return CrawledEndpoint(url=url, status_code=200, depth=0)


# ─────────────────────────────────────────────────────────────────────────────
# Finding tests
# ─────────────────────────────────────────────────────────────────────────────


class TestFinding:

    def test_default_id_is_unique(self) -> None:
        f1 = Finding()
        f2 = Finding()
        assert f1.id != f2.id

    def test_to_dict_contains_required_keys(self) -> None:
        f = Finding(
            title="Reflected XSS",
            severity=Severity.HIGH,
            url="http://target.com/search",
            parameter="q",
            payload="<script>alert(1)</script>",
            evidence="<script>alert(1)</script> found in response",
        )
        d = f.to_dict()
        for key in ("id", "title", "severity", "url", "parameter", "payload", "evidence"):
            assert key in d

    def test_severity_serialises_to_string(self) -> None:
        f = Finding(severity=Severity.CRITICAL)
        assert f.to_dict()["severity"] == "critical"

    def test_extra_field_preserved_in_dict(self) -> None:
        f = Finding(extra={"matched_pattern": r"You have an error"})
        assert f.to_dict()["extra"]["matched_pattern"] == r"You have an error"


# ─────────────────────────────────────────────────────────────────────────────
# Severity enum tests
# ─────────────────────────────────────────────────────────────────────────────


class TestSeverity:

    def test_all_expected_levels_exist(self) -> None:
        levels = {s.value for s in Severity}
        assert levels == {"critical", "high", "medium", "low", "informational"}

    def test_severity_is_string_comparable(self) -> None:
        assert Severity.HIGH == "high"


# ─────────────────────────────────────────────────────────────────────────────
# BaseScannerModule tests
# ─────────────────────────────────────────────────────────────────────────────


class TestBaseScannerModule:

    def _mock_requester(self) -> MagicMock:
        return MagicMock(spec=Requester)

    def test_concrete_module_runs_and_returns_findings(self) -> None:
        finding = Finding(title="Test Finding", severity=Severity.LOW)
        module = _EchoModule(self._mock_requester(), findings=[finding])
        results = module.run(_make_endpoint())
        assert len(results) == 1
        assert results[0].title == "Test Finding"

    def test_module_can_return_empty_list(self) -> None:
        module = _EchoModule(self._mock_requester(), findings=[])
        results = module.run(_make_endpoint())
        assert results == []

    def test_cannot_instantiate_base_directly(self) -> None:
        with pytest.raises(TypeError):
            BaseScannerModule(self._mock_requester())  # type: ignore[abstract]

    def test_module_repr(self) -> None:
        module = _EchoModule(self._mock_requester(), findings=[])
        assert "echo" in repr(module)

    def test_requester_is_accessible(self) -> None:
        req = self._mock_requester()
        module = _EchoModule(req, findings=[])
        assert module.requester is req
