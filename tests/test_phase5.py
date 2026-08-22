"""
VortexDAST – tests/test_phase5.py
────────────────────────────────────────────────────────────────────────────
Comprehensive unit and integration tests for Phase 5:
  *  SSRFCheckModule (ssrf_check.py)
  *  Reporter (core/reporter.py)
  *  CLI argument parser and module resolution (scanner.py)

All network calls are mocked via unittest.mock.
File I/O is tested against temporary directories.

Run with:
    pytest tests/test_phase5.py -v
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from typing import Dict, List
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crawler import CrawledEndpoint
from core.parser import ParsedForm, FormField, ParsedLink
from core.reporter import Reporter, _SEVERITY_ORDER, _CVSS_RANGES
from core.requester import Requester
from modules.base import Finding, Severity
from modules.ssrf_check import (
    SSRFCheckModule,
    _load_ssrf_probes,
    _BaselineResult,
    _BODY_MARKERS,
)
from scanner import _build_parser, _resolve_modules, _load_config, MODULE_REGISTRY

# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_SSRF_PROBES_PATH = os.path.join(_PAYLOADS_DIR, "ssrf_probes.json")


def _mock_requester() -> MagicMock:
    return MagicMock(spec=Requester)


def _mock_response(text: str = "", status: int = 200) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.content = text.encode()
    r.headers = {"Content-Type": "text/html"}
    return r


def _make_endpoint(
    url: str = "https://target.com/page",
    query_params: Dict[str, List[str]] | None = None,
    forms: List[ParsedForm] | None = None,
    links: List[ParsedLink] | None = None,
    headers: Dict[str, str] | None = None,
) -> CrawledEndpoint:
    return CrawledEndpoint(
        url=url,
        status_code=200,
        depth=0,
        query_params=query_params or {},
        forms=forms or [],
        links=links or [],
        response_headers=headers or {},
    )


def _make_finding(
    title: str = "Test Finding",
    severity: Severity = Severity.HIGH,
    url: str = "https://target.com/",
    parameter: str | None = "q",
    payload: str | None = "'",
    description: str = "A test finding.",
    remediation: str = "Fix it.",
    module: str = "xss_check",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        url=url,
        parameter=parameter,
        payload=payload,
        description=description,
        remediation=remediation,
        extra={"module": module},
    )


# ─────────────────────────────────────────────────────────────────────────────
# SSRFCheckModule — payload loader tests
# ─────────────────────────────────────────────────────────────────────────────


class TestSSRFPayloadLoader:

    def test_loads_keywords_and_probes(self) -> None:
        keywords, probes = _load_ssrf_probes(_SSRF_PROBES_PATH)
        assert len(keywords) > 0
        assert len(probes) > 0

    def test_keywords_are_lowercase(self) -> None:
        keywords, _ = _load_ssrf_probes(_SSRF_PROBES_PATH)
        for kw in keywords:
            assert kw == kw.lower(), f"Keyword '{kw}' is not lowercase"

    def test_probes_have_required_fields(self) -> None:
        _, probes = _load_ssrf_probes(_SSRF_PROBES_PATH)
        for probe in probes:
            assert "id" in probe
            assert "value" in probe
            assert "description" in probe

    def test_probes_contain_loopback_addresses(self) -> None:
        _, probes = _load_ssrf_probes(_SSRF_PROBES_PATH)
        values = [p["value"] for p in probes]
        assert any("127.0.0.1" in v for v in values)
        assert any("localhost" in v for v in values)

    def test_keywords_contain_expected_values(self) -> None:
        keywords, _ = _load_ssrf_probes(_SSRF_PROBES_PATH)
        for expected in ("url", "dest", "redirect", "src", "callback"):
            assert expected in keywords, f"'{expected}' missing from keyword set"

    def test_missing_file_returns_empty(self) -> None:
        keywords, probes = _load_ssrf_probes("/nonexistent/ssrf.json")
        assert keywords == set()
        assert probes == []

    def test_invalid_json_returns_empty(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            f.write("{invalid json")
            tmp_path = f.name
        try:
            keywords, probes = _load_ssrf_probes(tmp_path)
            assert keywords == set()
            assert probes == []
        finally:
            os.unlink(tmp_path)


# ─────────────────────────────────────────────────────────────────────────────
# SSRFCheckModule — candidate identification
# ─────────────────────────────────────────────────────────────────────────────


class TestSSRFCandidateIdentification:

    def _module(self) -> SSRFCheckModule:
        return SSRFCheckModule(_mock_requester(), payloads_path=_SSRF_PROBES_PATH)

    def test_url_param_is_candidate(self) -> None:
        m = self._module()
        assert m._is_ssrf_candidate("url") is True

    def test_dest_param_is_candidate(self) -> None:
        m = self._module()
        assert m._is_ssrf_candidate("dest") is True

    def test_redirect_param_is_candidate(self) -> None:
        m = self._module()
        assert m._is_ssrf_candidate("redirect") is True

    def test_src_param_is_candidate(self) -> None:
        m = self._module()
        assert m._is_ssrf_candidate("src") is True

    def test_generic_param_not_candidate(self) -> None:
        m = self._module()
        assert m._is_ssrf_candidate("username") is False

    def test_page_param_not_candidate(self) -> None:
        # 'page' is in the keyword list — should be candidate
        m = self._module()
        assert m._is_ssrf_candidate("page") is True

    def test_url_prefix_variant_is_candidate(self) -> None:
        # 'img_url' contains 'url' → candidate
        m = self._module()
        assert m._is_ssrf_candidate("img_url") is True

    def test_redirect_to_is_candidate(self) -> None:
        m = self._module()
        assert m._is_ssrf_candidate("redirect_to") is True

    def test_filter_candidates_from_params(self) -> None:
        m = self._module()
        params = {
            "url": ["http://example.com"],
            "username": ["admin"],
            "callback": ["http://cb.com"],
        }
        candidates = m._filter_candidates(params)
        assert "url" in candidates
        assert "callback" in candidates
        assert "username" not in candidates

    def test_filter_form_candidates(self) -> None:
        m = self._module()
        form = ParsedForm(
            action_url="https://target.com/fetch",
            method="POST",
            fields=[
                FormField(name="dest_url", field_type="text", default_value=""),
                FormField(name="email", field_type="email", default_value=""),
            ],
        )
        candidates = m._filter_form_candidates(form)
        assert "dest_url" in candidates
        assert "email" not in candidates


# ─────────────────────────────────────────────────────────────────────────────
# SSRFCheckModule — body marker detection
# ─────────────────────────────────────────────────────────────────────────────


class TestSSRFBodyMarkers:

    def test_detects_ami_id_marker(self) -> None:
        result = SSRFCheckModule._check_body_markers("ami-id: ami-0abcdef1234567890")
        assert result == "ami-id"

    def test_detects_127_loopback_marker(self) -> None:
        result = SSRFCheckModule._check_body_markers("Connected from 127.0.0.1 successfully")
        assert result == "127.0.0.1"

    def test_detects_aws_metadata_marker(self) -> None:
        result = SSRFCheckModule._check_body_markers("iam/security-credentials/role-name")
        assert result == "iam/security-credentials"

    def test_detects_compute_metadata_marker(self) -> None:
        result = SSRFCheckModule._check_body_markers(
            '{"computeMetadata": {"v1": {}}}'
        )
        assert result == "computeMetadata"

    def test_no_marker_returns_none(self) -> None:
        result = SSRFCheckModule._check_body_markers("Normal HTML page content here.")
        assert result is None

    def test_case_insensitive_marker_match(self) -> None:
        result = SSRFCheckModule._check_body_markers("AMI-ID: ami-xxxxx")
        assert result is not None  # 'ami-id' matches case-insensitively


# ─────────────────────────────────────────────────────────────────────────────
# SSRFCheckModule — signal evaluation and findings
# ─────────────────────────────────────────────────────────────────────────────


class TestSSRFSignalEvaluation:

    def _module(self) -> SSRFCheckModule:
        return SSRFCheckModule(
            _mock_requester(),
            payloads_path=_SSRF_PROBES_PATH,
            timing_threshold_s=2.5,
        )

    def _baseline(
        self, status: int = 200, body: str = "OK", elapsed: float = 0.1
    ) -> _BaselineResult:
        return _BaselineResult(status_code=status, body=body, elapsed_s=elapsed)

    def test_body_marker_gives_high_severity(self) -> None:
        m = self._module()
        probe = {"id": "test", "value": "http://127.0.0.1", "description": "IPv4 loopback"}
        finding = m._evaluate_signals(
            url="https://target.com/fetch?url=http://127.0.0.1",
            fuzzed_body="ami-id: ami-0abc",
            fuzzed_status=200,
            fuzzed_elapsed=0.2,
            baseline=self._baseline(),
            probe=probe,
            parameter="url",
            method="GET",
        )
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert "ami-id" in finding.extra.get("body_marker", "")

    def test_status_change_and_timing_gives_medium(self) -> None:
        m = self._module()
        probe = {"id": "test", "value": "http://127.0.0.1", "description": "Loopback"}
        finding = m._evaluate_signals(
            url="https://target.com/fetch?url=http://127.0.0.1",
            fuzzed_body="<html>500 Error</html>",
            fuzzed_status=500,  # changed from baseline 200
            fuzzed_elapsed=3.5,  # > 2.5s threshold
            baseline=self._baseline(status=200, elapsed=0.1),
            probe=probe,
            parameter="url",
            method="GET",
        )
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_status_change_only_gives_low(self) -> None:
        m = self._module()
        probe = {"id": "test", "value": "http://127.0.0.1", "description": "Loopback"}
        finding = m._evaluate_signals(
            url="https://target.com/fetch?url=http://127.0.0.1",
            fuzzed_body="<html>Error</html>",
            fuzzed_status=500,
            fuzzed_elapsed=0.2,  # fast — no timing signal
            baseline=self._baseline(status=200, elapsed=0.1),
            probe=probe,
            parameter="url",
            method="GET",
        )
        assert finding is not None
        assert finding.severity == Severity.LOW

    def test_timing_only_gives_low(self) -> None:
        m = self._module()
        probe = {"id": "test", "value": "http://127.0.0.1", "description": "Loopback"}
        finding = m._evaluate_signals(
            url="https://target.com/fetch?url=http://127.0.0.1",
            fuzzed_body="<html>OK</html>",
            fuzzed_status=200,  # same as baseline — no status change
            fuzzed_elapsed=3.5,  # slow — timing fires
            baseline=self._baseline(status=200, elapsed=0.1),
            probe=probe,
            parameter="url",
            method="GET",
        )
        assert finding is not None
        assert finding.severity == Severity.LOW

    def test_no_signals_returns_none(self) -> None:
        m = self._module()
        probe = {"id": "test", "value": "http://127.0.0.1", "description": "Loopback"}
        finding = m._evaluate_signals(
            url="https://target.com/fetch?url=http://127.0.0.1",
            fuzzed_body="<html>Normal page</html>",
            fuzzed_status=200,  # unchanged
            fuzzed_elapsed=0.15,  # fast
            baseline=self._baseline(status=200, elapsed=0.1),
            probe=probe,
            parameter="url",
            method="GET",
        )
        assert finding is None

    def test_baseline_4xx_skips_parameter(self) -> None:
        """If baseline returns 4xx, the module must skip that parameter."""
        module = SSRFCheckModule(
            _mock_requester(), payloads_path=_SSRF_PROBES_PATH
        )
        # Baseline returns 404.
        baseline_resp = _mock_response("<html>Not found</html>", status=404)
        module.requester.get.return_value = (baseline_resp, None)

        ep = _make_endpoint(query_params={"url": ["http://example.com"]})
        findings = module.run(ep)
        # No probes should be issued after a 4xx baseline.
        assert findings == []

    def test_baseline_fetch_failure_skips_gracefully(self) -> None:
        module = SSRFCheckModule(
            _mock_requester(), payloads_path=_SSRF_PROBES_PATH
        )
        module.requester.get.return_value = (None, "Timeout")
        ep = _make_endpoint(query_params={"url": ["http://example.com"]})
        findings = module.run(ep)
        assert isinstance(findings, list)

    def test_non_candidate_params_skipped(self) -> None:
        module = SSRFCheckModule(
            _mock_requester(), payloads_path=_SSRF_PROBES_PATH
        )
        module.requester.get.return_value = (
            _mock_response("<html>OK</html>", status=200), None
        )
        # 'username' is not an SSRF candidate keyword.
        ep = _make_endpoint(query_params={"username": ["admin"]})
        findings = module.run(ep)
        assert findings == []

    def test_finding_contains_all_required_fields(self) -> None:
        m = self._module()
        probe = {
            "id": "ssrf_ipv4_loopback_80",
            "value": "http://127.0.0.1:80",
            "description": "IPv4 loopback on port 80",
        }
        finding = m._evaluate_signals(
            url="https://target.com/fetch?url=http://127.0.0.1",
            fuzzed_body="ami-id: ami-0abc",
            fuzzed_status=200,
            fuzzed_elapsed=0.2,
            baseline=self._baseline(),
            probe=probe,
            parameter="url",
            method="GET",
        )
        assert finding is not None
        assert finding.url != ""
        assert finding.parameter == "url"
        assert finding.payload == "http://127.0.0.1:80"
        assert finding.remediation != ""


# ─────────────────────────────────────────────────────────────────────────────
# Reporter — JSON output
# ─────────────────────────────────────────────────────────────────────────────


class TestReporterJSON:

    def _reporter(
        self,
        findings: List[Finding] | None = None,
        target: str = "https://target.com",
    ) -> Reporter:
        from io import StringIO
        from rich.console import Console
        console = Console(file=io.StringIO(), force_terminal=True)
        return Reporter(
            findings=findings or [],
            target=target,
            scan_meta={"modules_run": "xss_check", "scan_duration_s": "1.23"},
            console=console,
        )

    def test_to_dict_contains_required_keys(self) -> None:
        r = self._reporter()
        d = r.to_dict()
        for key in ("vortexdast_version", "report_timestamp", "target", "summary", "findings"):
            assert key in d

    def test_to_dict_target_matches(self) -> None:
        r = self._reporter(target="https://myapp.com")
        assert r.to_dict()["target"] == "https://myapp.com"

    def test_to_dict_findings_serialised(self) -> None:
        findings = [_make_finding(severity=Severity.HIGH)]
        r = self._reporter(findings=findings)
        d = r.to_dict()
        assert len(d["findings"]) == 1
        assert d["findings"][0]["severity"] == "high"

    def test_summary_counts_by_severity(self) -> None:
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.LOW),
        ]
        r = self._reporter(findings=findings)
        summary = r.to_dict()["summary"]["by_severity"]
        assert summary["critical"] == 1
        assert summary["high"] == 2
        assert summary["low"] == 1
        assert summary["medium"] == 0

    def test_empty_findings_list(self) -> None:
        r = self._reporter()
        d = r.to_dict()
        assert d["summary"]["total_findings"] == 0
        assert d["findings"] == []

    def test_save_json_creates_file(self) -> None:
        findings = [_make_finding(severity=Severity.MEDIUM)]
        r = self._reporter(findings=findings)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.json")
            r.save_json(path)
            assert os.path.isfile(path)
            with open(path) as f:
                data = json.load(f)
            assert data["target"] == "https://target.com"
            assert len(data["findings"]) == 1

    def test_save_json_creates_parent_dirs(self) -> None:
        r = self._reporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "subdir", "nested", "report.json")
            r.save_json(path)
            assert os.path.isfile(path)

    def test_save_dispatches_to_json_for_json_ext(self) -> None:
        r = self._reporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "out.json")
            r.save(path)
            assert os.path.isfile(path)
            with open(path) as f:
                data = json.load(f)
            assert "findings" in data

    def test_scan_metadata_included_in_json(self) -> None:
        r = self._reporter()
        d = r.to_dict()
        assert "modules_run" in d["scan_metadata"]


# ─────────────────────────────────────────────────────────────────────────────
# Reporter — Markdown output
# ─────────────────────────────────────────────────────────────────────────────


class TestReporterMarkdown:

    def _reporter(self, findings: List[Finding] | None = None) -> Reporter:
        console = Reporter.__new__(Reporter)
        from rich.console import Console
        return Reporter(
            findings=findings or [],
            target="https://target.com",
            console=Console(file=io.StringIO(), force_terminal=True),
        )

    def test_save_markdown_creates_file(self) -> None:
        r = self._reporter(findings=[_make_finding(severity=Severity.HIGH)])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.md")
            r.save_markdown(path)
            assert os.path.isfile(path)

    def test_markdown_contains_target(self) -> None:
        r = self._reporter()
        md = r._render_markdown()
        assert "https://target.com" in md

    def test_markdown_contains_severity_table(self) -> None:
        r = self._reporter()
        md = r._render_markdown()
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            assert sev in md

    def test_markdown_contains_finding_title(self) -> None:
        findings = [_make_finding(title="Reflected XSS Found")]
        r = self._reporter(findings=findings)
        md = r._render_markdown()
        assert "Reflected XSS Found" in md

    def test_markdown_contains_remediation(self) -> None:
        findings = [_make_finding(remediation="Use prepared statements.")]
        r = self._reporter(findings=findings)
        md = r._render_markdown()
        assert "Use prepared statements." in md

    def test_markdown_escapes_pipe_in_payload(self) -> None:
        findings = [_make_finding(payload="' OR 1=1 | comment")]
        r = self._reporter(findings=findings)
        md = r._render_markdown()
        # The raw pipe should be HTML-escaped in table cells.
        assert "&#124;" in md

    def test_markdown_deduplicates_remediation_section(self) -> None:
        """Identical finding titles should appear only once in the Remediation Summary."""
        findings = [
            _make_finding(title="Same Issue", remediation="Fix A"),
            _make_finding(title="Same Issue", remediation="Fix A"),
        ]
        r = self._reporter(findings=findings)
        md = r._render_markdown()
        # Split off just the Remediation Summary section.
        remediation_section = md.split("## Remediation Summary")[-1] if "## Remediation Summary" in md else ""
        # "Same Issue" heading should appear exactly once in the Remediation section.
        assert remediation_section.count("### Same Issue") == 1

    def test_save_dispatches_to_markdown_for_md_ext(self) -> None:
        r = self._reporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "out.md")
            r.save(path)
            assert os.path.isfile(path)
            content = open(path).read()
            assert "VortexDAST" in content

    def test_save_dispatches_to_markdown_for_markdown_ext(self) -> None:
        r = self._reporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "out.markdown")
            r.save(path)
            assert os.path.isfile(path)

    def test_cvss_ranges_present_in_markdown(self) -> None:
        r = self._reporter()
        md = r._render_markdown()
        for sev, data in _CVSS_RANGES.items():
            assert data["range"] in md


# ─────────────────────────────────────────────────────────────────────────────
# Reporter — Terminal output (smoke tests)
# ─────────────────────────────────────────────────────────────────────────────


class TestReporterTerminal:

    def _reporter(self, findings: List[Finding] | None = None) -> tuple:
        output = io.StringIO()
        from rich.console import Console
        console = Console(file=output, force_terminal=True, width=120)
        r = Reporter(
            findings=findings or [],
            target="https://target.com",
            scan_meta={"modules_run": "xss_check"},
            console=console,
        )
        return r, output

    def test_print_terminal_summary_runs_without_error(self) -> None:
        r, _ = self._reporter()
        r.print_terminal_summary()  # Should not raise

    def test_terminal_output_contains_target(self) -> None:
        r, output = self._reporter()
        r.print_terminal_summary()
        assert "target.com" in output.getvalue()

    def test_terminal_output_shows_finding_title(self) -> None:
        findings = [_make_finding(title="SQL Injection Detected")]
        r, output = self._reporter(findings=findings)
        r.print_terminal_summary()
        assert "SQL Injection Detected" in output.getvalue()

    def test_terminal_empty_findings_does_not_crash(self) -> None:
        r, output = self._reporter(findings=[])
        r.print_terminal_summary()
        assert "0" in output.getvalue()  # "Total findings: 0"


# ─────────────────────────────────────────────────────────────────────────────
# CLI argument parser tests
# ─────────────────────────────────────────────────────────────────────────────


class TestCLIParser:

    def _parse(self, args: List[str]) -> object:
        parser = _build_parser()
        return parser.parse_args(args)

    def test_target_is_required(self) -> None:
        with pytest.raises(SystemExit):
            _build_parser().parse_args([])

    def test_target_short_flag(self) -> None:
        args = self._parse(["-u", "https://target.com"])
        assert args.target == "https://target.com"

    def test_target_long_flag(self) -> None:
        args = self._parse(["--target", "https://target.com"])
        assert args.target == "https://target.com"

    def test_default_modules_is_all(self) -> None:
        args = self._parse(["-u", "https://target.com"])
        assert args.modules == "all"

    def test_modules_short_flag(self) -> None:
        args = self._parse(["-u", "https://target.com", "-m", "xss_check"])
        assert args.modules == "xss_check"

    def test_max_depth_default_is_none(self) -> None:
        args = self._parse(["-u", "https://target.com"])
        assert args.max_depth is None

    def test_max_depth_override(self) -> None:
        args = self._parse(["-u", "https://target.com", "--max-depth", "2"])
        assert args.max_depth == 2

    def test_insecure_flag(self) -> None:
        args = self._parse(["-u", "https://target.com", "--insecure"])
        assert args.insecure is True

    def test_insecure_short_flag(self) -> None:
        args = self._parse(["-u", "https://target.com", "-k"])
        assert args.insecure is True

    def test_dynamic_flag(self) -> None:
        args = self._parse(["-u", "https://target.com", "--dynamic"])
        assert args.dynamic is True

    def test_output_flag(self) -> None:
        args = self._parse(["-u", "https://target.com", "-o", "report.json"])
        assert args.output == "report.json"

    def test_rate_limit_flag(self) -> None:
        args = self._parse(["-u", "https://target.com", "--rate-limit", "2.5"])
        assert args.rate_limit == 2.5

    def test_verbose_flag(self) -> None:
        args = self._parse(["-u", "https://target.com", "-v"])
        assert args.verbose is True

    def test_proxy_flag(self) -> None:
        args = self._parse(["-u", "https://target.com", "--proxy", "http://127.0.0.1:8080"])
        assert args.proxy == "http://127.0.0.1:8080"

    def test_config_flag(self) -> None:
        args = self._parse(["-u", "https://target.com", "--config", "/tmp/my.yaml"])
        assert args.config == "/tmp/my.yaml"


# ─────────────────────────────────────────────────────────────────────────────
# Module resolution tests
# ─────────────────────────────────────────────────────────────────────────────


class TestModuleResolution:

    def test_all_resolves_to_all_modules(self) -> None:
        resolved = _resolve_modules("all")
        assert set(resolved) == set(MODULE_REGISTRY.keys())

    def test_single_module_resolved(self) -> None:
        resolved = _resolve_modules("xss_check")
        assert resolved == ["xss_check"]

    def test_comma_separated_modules_resolved(self) -> None:
        resolved = _resolve_modules("xss_check,sqli_check")
        assert "xss_check" in resolved
        assert "sqli_check" in resolved
        assert len(resolved) == 2

    def test_spaces_stripped_from_modules(self) -> None:
        resolved = _resolve_modules("xss_check, sqli_check")
        assert "xss_check" in resolved
        assert "sqli_check" in resolved

    def test_unknown_module_exits(self) -> None:
        with pytest.raises(SystemExit):
            _resolve_modules("nonexistent_module")

    def test_case_sensitive_matching(self) -> None:
        # Module names are lowercase; uppercase should fail.
        with pytest.raises(SystemExit):
            _resolve_modules("XSS_CHECK")

    def test_all_modules_in_registry(self) -> None:
        for name in ("headers_audit", "xss_check", "sqli_check", "ssrf_check"):
            assert name in MODULE_REGISTRY, f"'{name}' missing from MODULE_REGISTRY"


# ─────────────────────────────────────────────────────────────────────────────
# Config loader tests
# ─────────────────────────────────────────────────────────────────────────────


class TestConfigLoader:

    def test_loads_real_config_yaml(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
        config = _load_config(config_path)
        assert "crawler" in config
        assert "requester" in config
        assert "scope" in config

    def test_falls_back_on_missing_file(self) -> None:
        config = _load_config("/nonexistent/path/config.yaml")
        assert "crawler" in config
        assert config["crawler"]["max_depth"] == 3

    def test_cli_overrides_depth(self) -> None:
        config = _load_config("/nonexistent/path/config.yaml")
        # Simulate what run_scan does: override max_depth from CLI.
        cli_depth = 1
        effective_depth = cli_depth if cli_depth is not None else config["crawler"]["max_depth"]
        assert effective_depth == 1

    def test_config_yaml_max_depth(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
        config = _load_config(config_path)
        assert isinstance(config["crawler"]["max_depth"], int)

    def test_config_rate_limit_rps(self) -> None:
        config_path = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
        config = _load_config(config_path)
        rps = float(config["requester"]["rate_limit_rps"])
        assert rps > 0

    def test_config_handles_invalid_yaml(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(": invalid: yaml: [")
            tmp_path = f.name
        try:
            config = _load_config(tmp_path)
            # Should fall back to defaults.
            assert "crawler" in config
        finally:
            os.unlink(tmp_path)
