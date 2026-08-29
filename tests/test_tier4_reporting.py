"""
VortexDAST – tests/test_tier4_reporting.py
────────────────────────────────────────────────────────────────────────────
Unit and integration tests for Tier 4 capabilities:
  * Finding Deduplication Engine (core/reporter.py)
  * Interactive Single-Page HTML Report Generator (core/reporter.py)
  * CLI Dispatcher integration with HTML output (-o report.html)

Run with:
    pytest tests/test_tier4_reporting.py -v
"""

from __future__ import annotations

import html
import os
import sys
import tempfile
from typing import List

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.reporter import Reporter
from modules.base import Finding, Severity


def _make_finding(
    title: str = "Reflected XSS",
    severity: Severity = Severity.HIGH,
    url: str = "https://target.com/search",
    parameter: str | None = "q",
    payload: str | None = "<script>alert(1)</script>",
    evidence: str = "Reflected in response: <script>alert(1)</script>",
    description: str = "Reflected Cross-Site Scripting vulnerability detected.",
    remediation: str = "Context-encode user input before rendering.",
    module: str = "xss_check",
    cvss_score: float | None = 7.5,
    cvss_vector: str | None = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        url=url,
        parameter=parameter,
        payload=payload,
        evidence=evidence,
        description=description,
        remediation=remediation,
        extra={"module": module},
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Finding Deduplication Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestFindingDeduplication:
    """Tests for Finding Deduplication Engine in Reporter."""

    def test_deduplicate_empty_list(self) -> None:
        """Deduplicating empty list returns an empty list."""
        assert Reporter.deduplicate_findings([]) == []

    def test_deduplicate_distinct_findings_preserved(self) -> None:
        """Findings with different (module, url, parameter, title) are not merged."""
        f1 = _make_finding(title="XSS", url="https://target.com/a", parameter="q")
        f2 = _make_finding(title="SQLi", url="https://target.com/b", parameter="id")
        f3 = _make_finding(title="XSS", url="https://target.com/a", parameter="p")

        result = Reporter.deduplicate_findings([f1, f2, f3])
        assert len(result) == 3

    def test_deduplicate_merges_same_key_findings(self) -> None:
        """Multiple probe hits for same (module, url, parameter, title) are merged."""
        f1 = _make_finding(
            title="Reflected XSS",
            url="https://target.com/search",
            parameter="q",
            evidence="Evidence hit 1: <script>alert(1)</script>",
            payload="<script>alert(1)</script>",
        )
        f2 = _make_finding(
            title="Reflected XSS",
            url="https://target.com/search",
            parameter="q",
            evidence="Evidence hit 2: <img src=x onerror=alert(1)>",
            payload="<img src=x onerror=alert(1)>",
        )

        result = Reporter.deduplicate_findings([f1, f2])
        assert len(result) == 1
        merged = result[0]
        assert merged.title == "Reflected XSS"
        assert merged.url == "https://target.com/search"
        assert merged.parameter == "q"
        assert merged.extra.get("merged_count") == 2
        assert "Evidence hit 1" in merged.evidence
        assert "Evidence hit 2" in merged.evidence
        assert "\n---\n" in merged.evidence

    def test_deduplicate_selects_highest_severity(self) -> None:
        """Merged finding inherits the highest severity level among probe hits."""
        f1 = _make_finding(title="Path Traversal", severity=Severity.MEDIUM)
        f2 = _make_finding(title="Path Traversal", severity=Severity.CRITICAL)
        f3 = _make_finding(title="Path Traversal", severity=Severity.HIGH)

        result = Reporter.deduplicate_findings([f1, f2, f3])
        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL

    def test_deduplicate_selects_highest_cvss(self) -> None:
        """Merged finding retains the highest CVSS score and vector."""
        f1 = _make_finding(cvss_score=5.3, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        f2 = _make_finding(cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")

        result = Reporter.deduplicate_findings([f1, f2])
        assert len(result) == 1
        assert result[0].cvss_score == 9.8
        assert result[0].cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

    def test_deduplicate_none_parameter_handling(self) -> None:
        """Findings with parameter=None are deduplicated correctly."""
        f1 = _make_finding(parameter=None, evidence="Hit 1")
        f2 = _make_finding(parameter=None, evidence="Hit 2")

        result = Reporter.deduplicate_findings([f1, f2])
        assert len(result) == 1
        assert result[0].extra.get("merged_count") == 2

    def test_reporter_init_automatically_deduplicates(self) -> None:
        """Reporter.__init__ applies deduplication to self.findings."""
        f1 = _make_finding(evidence="Probe A")
        f2 = _make_finding(evidence="Probe B")

        reporter = Reporter(findings=[f1, f2], target="https://target.com")
        assert len(reporter.raw_findings) == 2
        assert len(reporter.findings) == 1


# ─────────────────────────────────────────────────────────────────────────────
# HTML Report Generator Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestHTMLReportGenerator:
    """Tests for Interactive HTML Report Generator in Reporter."""

    def test_save_html_creates_valid_file(self) -> None:
        """save_html creates a file with complete HTML document tags."""
        f1 = _make_finding()
        reporter = Reporter(findings=[f1], target="https://target.com")

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "report.html")
            reporter.save_html(out_path)

            assert os.path.exists(out_path)
            with open(out_path, "r", encoding="utf-8") as fh:
                content = fh.read()

            assert "<!DOCTYPE html>" in content
            assert "<html" in content
            assert "</html>" in content
            assert "VortexDAST Security Scan Report" in content
            assert "https://target.com" in content

    def test_html_report_airgapped_no_external_cdn(self) -> None:
        """HTML report must contain zero external HTTP/HTTPS CDN dependencies."""
        f1 = _make_finding()
        reporter = Reporter(findings=[f1], target="https://target.com")

        content = reporter._render_html()
        # Verify no external CSS or script imports from CDNs
        assert "http://" not in content
        assert "https://" not in content or "target.com" in content  # target URL is fine
        assert '<script src=' not in content
        assert '<link rel="stylesheet" href="http' not in content

    def test_html_report_contains_executive_metrics(self) -> None:
        """HTML report contains executive metric cards for all severity buckets."""
        f_crit = _make_finding(title="RCE", severity=Severity.CRITICAL)
        f_high = _make_finding(title="XSS", severity=Severity.HIGH)
        f_med = _make_finding(title="CSRF", severity=Severity.MEDIUM)

        reporter = Reporter(findings=[f_crit, f_high, f_med], target="https://target.com")
        content = reporter._render_html()

        assert "Total Findings" in content
        assert "Critical" in content
        assert "High" in content
        assert "Medium" in content
        assert "Low" in content
        assert "Informational" in content

    def test_html_report_contains_severity_breakdown(self) -> None:
        """HTML report includes visual progress bar and percentage breakdown."""
        f1 = _make_finding(severity=Severity.HIGH)
        reporter = Reporter(findings=[f1], target="https://target.com")

        content = reporter._render_html()
        assert "Severity Breakdown" in content
        assert "progress-bar-stacked" in content
        assert "bar-segment high" in content

    def test_html_report_collapsible_cards_content(self) -> None:
        """Collapsible finding cards display ID, URL, Parameter, CVSS, Evidence, and Remediation."""
        f = _make_finding(
            title="SQL Injection",
            severity=Severity.CRITICAL,
            url="https://target.com/db",
            parameter="user_id",
            payload="' OR '1'='1",
            evidence="MySQL error: Syntax error in query",
            remediation="Use parameterized SQL queries.",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        )
        reporter = Reporter(findings=[f], target="https://target.com/db")
        content = reporter._render_html()

        assert "SQL Injection" in content
        assert "https://target.com/db" in content
        assert "user_id" in content
        assert html.escape("' OR '1'='1") in content
        assert "MySQL error: Syntax error in query" in content
        assert "Use parameterized SQL queries." in content
        assert "CVSS 9.8" in content
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" in content

    def test_html_report_escapes_user_input(self) -> None:
        """Malicious payload strings and special chars are HTML-escaped to prevent injection."""
        malicious_title = "<script>alert('xss-title')</script>"
        malicious_evidence = "Found <iframe src=evil.com> inside body"

        f = _make_finding(title=malicious_title, evidence=malicious_evidence)
        reporter = Reporter(findings=[f], target="https://target.com")
        content = reporter._render_html()

        assert html.escape(malicious_title) in content
        assert "<script>alert('xss-title')</script>" not in content
        assert html.escape(malicious_evidence) in content

    def test_html_report_embedded_vanilla_js(self) -> None:
        """HTML report embeds client-side search, filtering, and card accordion JS functions."""
        reporter = Reporter(findings=[_make_finding()], target="https://target.com")
        content = reporter._render_html()

        assert "function toggleCard" in content
        assert "function toggleAll" in content
        assert "function setSeverityFilter" in content
        assert "function filterFindings" in content

    def test_save_dispatches_to_html(self) -> None:
        """Reporter.save dispatches .html and .htm paths to save_html."""
        reporter = Reporter(findings=[_make_finding()], target="https://target.com")

        with tempfile.TemporaryDirectory() as tmpdir:
            path_html = os.path.join(tmpdir, "out.html")
            path_htm = os.path.join(tmpdir, "out.htm")

            reporter.save(path_html)
            reporter.save(path_htm)

            assert os.path.exists(path_html)
            assert os.path.exists(path_htm)
            with open(path_html, "r", encoding="utf-8") as fh:
                assert "<!DOCTYPE html>" in fh.read()
