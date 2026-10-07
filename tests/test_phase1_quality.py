"""
VortexDAST – tests/test_phase1_quality.py
Confidence levels, finding filters/suppression, and recon-module hardening.
"""

from __future__ import annotations

import os
import sys
import threading
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.filters import FilterConfigError, FindingFilter, load_suppression_rules
from core.reporter import Reporter
from modules.base import Confidence, Finding, Severity
from modules.dir_fuzzer import DirFuzzerModule
from modules.param_fuzzer import ParamFuzzerModule
from modules.tech_detect import TechDetectModule
from scanner import _build_parser, run_scan
from tests.test_recon_modules import _make_endpoint, _mock_requester, _mock_response

_ROOT = os.path.join(os.path.dirname(__file__), "..")


def _finding(**kw: Any) -> Finding:
    kw.setdefault("title", "Reflected XSS")
    kw.setdefault("url", "https://t.com/a")
    kw.setdefault("severity", Severity.HIGH)
    kw.setdefault("extra", {"module": "xss_check"})
    return Finding(**kw)


def _write(tmp_path: Any, text: str) -> str:
    p = tmp_path / "suppress.yaml"
    p.write_text(text)
    return str(p)


# ── Confidence model ────────────────────────────────────────────────────────


class TestConfidence:
    def test_default_is_firm_and_serialised(self) -> None:
        f = _finding()
        assert f.confidence == Confidence.FIRM
        assert f.to_dict()["confidence"] == "firm"

    def test_dedup_keeps_strongest_confidence(self) -> None:
        group = [
            _finding(confidence=Confidence.TENTATIVE, payload="a"),
            _finding(confidence=Confidence.CERTAIN, payload="b"),
            _finding(confidence=Confidence.FIRM, payload="c"),
        ]
        merged = Reporter.deduplicate_findings(group)
        assert len(merged) == 1
        assert merged[0].confidence == Confidence.CERTAIN

    def test_markdown_report_shows_confidence(self) -> None:
        rep = Reporter([_finding(confidence=Confidence.TENTATIVE)], "https://t.com", console=MagicMock())
        assert "| **Confidence** | Tentative |" in rep._render_markdown()

    def test_html_report_shows_confidence(self) -> None:
        rep = Reporter([_finding(confidence=Confidence.CERTAIN)], "https://t.com", console=MagicMock())
        assert '<td class="label">Confidence</td><td>Certain</td>' in rep._render_html()


# ── Finding filter ──────────────────────────────────────────────────────────


class TestFindingFilter:
    def test_min_severity(self) -> None:
        kept, dropped = FindingFilter(min_severity="medium").apply(
            [_finding(severity=Severity.HIGH), _finding(severity=Severity.MEDIUM), _finding(severity=Severity.LOW)]
        )
        assert [f.severity for f in kept] == [Severity.HIGH, Severity.MEDIUM]
        assert "min-severity" in dropped[0][1]

    def test_min_confidence(self) -> None:
        kept, dropped = FindingFilter(min_confidence="firm").apply(
            [_finding(confidence=Confidence.CERTAIN), _finding(confidence=Confidence.TENTATIVE)]
        )
        assert [f.confidence for f in kept] == [Confidence.CERTAIN]
        assert len(dropped) == 1

    def test_invalid_threshold_rejected(self) -> None:
        with pytest.raises(FilterConfigError):
            FindingFilter(min_severity="severe")

    def test_rule_requires_all_fields_to_match(self, tmp_path: Any) -> None:
        rules = load_suppression_rules(_write(tmp_path, """
suppress:
  - module: xss_check
    url: "/admin/"
    reason: accepted
"""))
        kept, dropped = FindingFilter(rules=rules).apply([
            _finding(url="https://t.com/admin/x"),
            _finding(url="https://t.com/public"),
            _finding(url="https://t.com/admin/y", extra={"module": "sqli_check"}),
        ])
        assert [f.url for f in kept] == ["https://t.com/public", "https://t.com/admin/y"]
        assert dropped[0][1] == "suppression rule: accepted"

    def test_parameter_regex_ignores_findings_without_parameter(self, tmp_path: Any) -> None:
        rules = load_suppression_rules(_write(tmp_path, 'suppress:\n  - parameter: "^csrf"\n'))
        kept, _ = FindingFilter(rules=rules).apply([_finding(parameter=None), _finding(parameter="csrf_token")])
        assert [f.parameter for f in kept] == [None]

    @pytest.mark.parametrize("body, message", [
        ("suppress:\n  - reason: everything\n", "at least one match field"),
        ("suppress:\n  - modul: xss_check\n", "unknown key"),
        ("suppress:\n  - url: '(['\n", "invalid regex"),
        ("suppress: nope\n", "top-level 'suppress:' list"),
        ("suppress: [\n", "invalid YAML"),
    ])
    def test_invalid_rule_files_rejected(self, tmp_path: Any, body: str, message: str) -> None:
        with pytest.raises(FilterConfigError, match=message):
            load_suppression_rules(_write(tmp_path, body))

    def test_missing_rule_file_rejected(self) -> None:
        with pytest.raises(FilterConfigError, match="cannot read"):
            load_suppression_rules("/nonexistent/suppress.yaml")

    def test_example_file_is_valid(self) -> None:
        assert len(load_suppression_rules(os.path.join(_ROOT, "suppress.example.yaml"))) == 3

    def test_bad_suppress_file_aborts_before_scanning(self) -> None:
        args = _build_parser().parse_args(["-u", "http://127.0.0.1:9", "--suppress", "/nonexistent.yaml"])
        assert run_scan(args) == 1

    def test_cli_rejects_unknown_confidence(self) -> None:
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["-u", "http://x", "--min-confidence", "maybe"])


# ── Recon module hardening ──────────────────────────────────────────────────


class TestDirFuzzerHardening:
    def test_catch_all_403_not_reported(self) -> None:
        req = _mock_requester()
        req.get.side_effect = lambda url, **kw: (_mock_response("Access denied by WAF", 403), None)
        assert DirFuzzerModule(req).run(_make_endpoint("https://target.com/")) == []

    def test_catch_all_403_still_reports_distinct_response(self) -> None:
        req = _mock_requester()

        def _get(url: str, **kw: Any) -> Any:
            if url.endswith("/.env"):
                return _mock_response("DB_PASSWORD=hunter2\nAPI_KEY=abc", 200), None
            return _mock_response("Access denied by WAF", 403), None

        req.get.side_effect = _get
        findings = DirFuzzerModule(req).run(_make_endpoint("https://target.com/"))
        assert [f.parameter for f in findings] == ["/.env"]
        assert findings[0].confidence == Confidence.CERTAIN

    def test_concurrent_runs_probe_origin_once(self) -> None:
        req = _mock_requester()
        req.get.side_effect = lambda url, **kw: (_mock_response("nf", 404), None)
        mod = DirFuzzerModule(req)
        barrier = threading.Barrier(8)

        def _run() -> None:
            barrier.wait()
            mod.run(_make_endpoint("https://target.com/page"))

        threads = [threading.Thread(target=_run) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert req.dispatch_concurrent.call_count == 1


class TestParamFuzzerHardening:
    def test_natural_page_jitter_not_reported(self) -> None:
        """Pages whose length varies on every load shouldn't yield length-delta findings."""
        req = _mock_requester()
        calls = {"n": 0}

        def _get(url: str, **kw: Any) -> Any:
            calls["n"] += 1
            padding = "x" * (400 if calls["n"] % 2 else 0)
            return _mock_response(f"<html>{padding}content</html>", 200), None

        req.get.side_effect = _get
        assert ParamFuzzerModule(req).run(_make_endpoint("https://target.com/feed")) == []

    def test_heuristic_only_hits_are_tentative(self) -> None:
        req = _mock_requester()

        def _get(url: str, **kw: Any) -> Any:
            if "query=" in url:
                return _mock_response("<html>Hello user. Query: test</html>", 200), None
            return _mock_response("<html>Hello user</html>", 200), None

        req.get.side_effect = _get
        findings = ParamFuzzerModule(req).run(_make_endpoint("https://target.com/search"))
        assert findings and all(f.confidence == Confidence.TENTATIVE for f in findings)

    def test_status_bypass_is_firm(self) -> None:
        req = _mock_requester()

        def _get(url: str, **kw: Any) -> Any:
            if "admin=" in url:
                return _mock_response("<html>Admin panel</html>", 200), None
            return _mock_response("Forbidden", 403), None

        req.get.side_effect = _get
        findings = ParamFuzzerModule(req).run(_make_endpoint("https://target.com/panel"))
        admin = [f for f in findings if f.parameter == "admin"]
        assert admin and admin[0].confidence == Confidence.FIRM


class TestTechDetectHardening:
    def test_concurrent_runs_report_each_tech_once(self) -> None:
        req = _mock_requester()
        req.get.return_value = (_mock_response("<html></html>", 200, headers={"Server": "nginx/1.25.3"}), None)
        mod = TechDetectModule(req)
        ep = _make_endpoint("https://target.com/", headers={"Server": "nginx/1.25.3"})
        results: list = []
        barrier = threading.Barrier(8)

        def _run() -> None:
            barrier.wait()
            results.extend(mod.run(ep))

        threads = [threading.Thread(target=_run) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        nginx = [f for f in results if "nginx" in f.title.lower()]
        assert len(nginx) == 1
        assert nginx[0].confidence == Confidence.CERTAIN
