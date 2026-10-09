"""
VortexDAST – tests/test_orchestrator.py
────────────────────────────────────────────────────────────────────────────
Tests for the orchestration foundation (``core/orchestrator.py``) and the
nuclei adapter (``adapters/nuclei_adapter.py``).

Adapter logic is exercised **without the real tool installed** by pointing the
adapter at a fake binary — a tiny fixture script that emits canned JSONL on
stdout — exactly as the roadmap (IMPROVEMENTS.md §4, Phase A) prescribes. This
keeps the suite hermetic: no network, no nuclei, no template downloads.
"""

from __future__ import annotations

import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest

# Allow imports from project root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from adapters.nuclei_adapter import NucleiAdapter
from core.orchestrator import (
    ScanContext,
    ToolAdapter,
    available_tools,
    discover_adapters,
    list_tools,
    parse_jsonl,
    run_command,
    severity_from_label,
)
from modules.base import Confidence, Finding, Severity


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures: fake tool binaries
# ─────────────────────────────────────────────────────────────────────────────

_NUCLEI_JSONL = textwrap.dedent(
    """\
    {"template-id":"CVE-2021-1234","info":{"name":"Example RCE","severity":"critical","description":"Remote code execution.","remediation":"Patch now.","tags":["cve","rce"],"reference":["https://example.test/cve"],"classification":{"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cvss-score":9.8,"cve-id":["CVE-2021-1234"],"cwe-id":["CWE-78"]}},"type":"http","host":"app.local","matched-at":"https://app.local/vuln","matcher-name":"word","curl-command":"curl -X GET https://app.local/vuln"}
    {"template-id":"tech-detect","info":{"name":"Nginx Detected","severity":"info"},"type":"http","host":"app.local","matched-at":"https://app.local/"}
    not-valid-json-line
    {"template-id":"missing-cvss","info":{"name":"Vector only","severity":"medium","classification":{"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}},"matched-at":"https://app.local/x"}
    """
)


def _write_fake_binary(dir_path: Path, name: str, stdout: str, exit_code: int = 0) -> Path:
    """Create an executable shell script that prints ``stdout`` and exits."""
    script = dir_path / name
    # Heredoc keeps the canned payload intact regardless of quoting.
    script.write_text(
        "#!/usr/bin/env bash\n"
        "cat <<'VORTEX_EOF'\n"
        f"{stdout}"
        "VORTEX_EOF\n"
        f"exit {exit_code}\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


@pytest.fixture
def fake_nuclei_on_path(tmp_path, monkeypatch):
    """Put a fake ``nuclei`` binary first on PATH; yield its directory."""
    _write_fake_binary(tmp_path, "nuclei", _NUCLEI_JSONL)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    return tmp_path


# ─────────────────────────────────────────────────────────────────────────────
# run_command: argv-safe subprocess runner
# ─────────────────────────────────────────────────────────────────────────────


class TestRunCommand:
    def test_captures_stdout(self):
        result = run_command(["printf", "hello"], timeout=5)
        assert result.ok
        assert result.returncode == 0
        assert result.stdout == "hello"

    def test_missing_binary_is_reported_not_raised(self):
        result = run_command(["vortex-nonexistent-binary-xyz"], timeout=5)
        assert result.not_found is True
        assert result.ok is False

    def test_timeout_is_reported_not_raised(self):
        result = run_command(["sleep", "5"], timeout=0.2)
        assert result.timed_out is True
        assert result.ok is False

    def test_nonzero_exit_is_captured(self):
        result = run_command(["bash", "-c", "exit 3"], timeout=5)
        assert result.returncode == 3
        assert result.ok is True  # ran to completion, just non-zero

    def test_empty_argv_rejected(self):
        with pytest.raises(ValueError):
            run_command([], timeout=5)

    def test_no_shell_interpolation(self, tmp_path):
        """A shell metacharacter in an arg is literal, never executed."""
        sentinel = tmp_path / "pwned"
        # If this were run through a shell, the ';' would create the file.
        result = run_command(["printf", "%s", f"; touch {sentinel}"], timeout=5)
        assert result.ok
        assert not sentinel.exists()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers: JSONL parsing + severity mapping
# ─────────────────────────────────────────────────────────────────────────────


class TestHelpers:
    def test_parse_jsonl_skips_blank_and_malformed(self):
        raw = '{"a":1}\n\n  \nnot-json\n{"b":2}\n'
        rows = list(parse_jsonl(raw))
        assert rows == [{"a": 1}, {"b": 2}]

    def test_parse_jsonl_empty(self):
        assert list(parse_jsonl("")) == []

    @pytest.mark.parametrize(
        "label,expected",
        [
            ("critical", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("Medium", Severity.MEDIUM),
            ("moderate", Severity.MEDIUM),
            ("low", Severity.LOW),
            ("info", Severity.INFORMATIONAL),
            ("unknown", Severity.INFORMATIONAL),
            (None, Severity.INFORMATIONAL),
            ("garbage", Severity.INFORMATIONAL),
        ],
    )
    def test_severity_from_label(self, label, expected):
        assert severity_from_label(label) == expected


# ─────────────────────────────────────────────────────────────────────────────
# ToolAdapter base: detection + fallback
# ─────────────────────────────────────────────────────────────────────────────


class _StubAdapter(ToolAdapter):
    name = "stub"
    binary = "vortex-nonexistent-binary-xyz"

    def build_command(self, target, ctx):
        return [self.binary, target]

    def parse(self, raw_output):
        return [Finding(title="should-not-happen")]


class TestToolAdapterBase:
    def test_is_available_false_for_missing_binary(self):
        assert _StubAdapter().is_available() is False

    def test_run_falls_back_when_unavailable(self):
        # Default fallback returns no findings rather than raising.
        assert _StubAdapter().run("https://app.local", ScanContext()) == []

    def test_fallback_override_is_used(self):
        class WithFallback(_StubAdapter):
            name = "stub-fb"

            def _fallback(self, target, ctx):
                return [Finding(title="fallback")]

        out = WithFallback().run("https://app.local", ScanContext())
        assert len(out) == 1 and out[0].title == "fallback"


# ─────────────────────────────────────────────────────────────────────────────
# Adapter discovery / registry
# ─────────────────────────────────────────────────────────────────────────────


class TestDiscovery:
    def test_nuclei_is_discovered(self):
        registry = discover_adapters()
        assert "nuclei" in registry
        assert registry["nuclei"] is NucleiAdapter

    def test_available_tools_lists_nuclei(self):
        assert "nuclei" in available_tools()

    def test_list_tools_reports_install_state(self):
        rows = {r["name"]: r for r in list_tools()}
        assert "nuclei" in rows
        assert rows["nuclei"]["binary"] == "nuclei"
        assert isinstance(rows["nuclei"]["installed"], bool)


# ─────────────────────────────────────────────────────────────────────────────
# NucleiAdapter: command building + parsing
# ─────────────────────────────────────────────────────────────────────────────


class TestNucleiAdapter:
    def test_build_command_is_argv_list_with_jsonl(self):
        argv = NucleiAdapter().build_command("https://app.local", ScanContext())
        assert argv[0] == "nuclei"
        assert "-jsonl" in argv
        assert "https://app.local" in argv
        # Target is a single argv element — never concatenated into a string.
        assert argv.count("https://app.local") == 1

    def test_parse_maps_records_to_findings(self):
        findings = NucleiAdapter().parse(_NUCLEI_JSONL)
        # 3 valid JSON objects; the malformed line is skipped.
        assert len(findings) == 3

        crit = findings[0]
        assert crit.title == "Example RCE"
        assert crit.severity == Severity.CRITICAL
        assert crit.confidence == Confidence.FIRM
        assert crit.url == "https://app.local/vuln"
        assert crit.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert crit.cvss_score == 9.8
        assert crit.extra["tool"] == "nuclei"
        assert crit.extra["template_id"] == "CVE-2021-1234"
        assert crit.extra["cve_id"] == ["CVE-2021-1234"]
        assert "template=CVE-2021-1234" in crit.evidence

    def test_parse_computes_score_from_vector_when_absent(self):
        findings = NucleiAdapter().parse(_NUCLEI_JSONL)
        vec_only = [f for f in findings if f.title == "Vector only"][0]
        assert vec_only.severity == Severity.MEDIUM
        assert vec_only.cvss_vector is not None
        # Score derived via core.cvss.calculate for this known vector.
        assert vec_only.cvss_score == 6.1

    def test_parse_handles_info_finding_without_classification(self):
        findings = NucleiAdapter().parse(_NUCLEI_JSONL)
        info = [f for f in findings if f.title == "Nginx Detected"][0]
        assert info.severity == Severity.INFORMATIONAL
        assert info.cvss_vector is None
        assert info.cvss_score is None

    def test_parse_empty_output(self):
        assert NucleiAdapter().parse("") == []

    def test_run_end_to_end_with_fake_binary(self, fake_nuclei_on_path):
        """Full run() path: detect fake nuclei on PATH, execute, parse."""
        adapter = NucleiAdapter()
        assert adapter.is_available() is True
        findings = adapter.run("https://app.local", ScanContext())
        assert len(findings) == 3
        assert any(f.severity == Severity.CRITICAL for f in findings)
