"""
VortexDAST – tests/test_phase2_html.py
HTML report confidence/module filters.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.reporter import Reporter
from modules.base import Confidence, Finding, Severity


def _html(findings: list) -> str:
    return Reporter(findings, "https://t.com", console=MagicMock())._render_html()


def _f(module: str, conf: Confidence, title: str = "Issue") -> Finding:
    return Finding(title=title, url=f"https://t.com/{title}", severity=Severity.LOW,
                   confidence=conf, extra={"module": module})


def test_cards_carry_confidence_and_module() -> None:
    out = _html([_f("sqli_check", Confidence.TENTATIVE)])
    assert 'data-confidence="tentative" data-module="sqli_check"' in out


def test_confidence_options_show_only_present_levels_with_counts() -> None:
    out = _html([_f("a", Confidence.CERTAIN, "x"), _f("a", Confidence.CERTAIN, "y"), _f("b", Confidence.TENTATIVE)])
    assert '<option value="certain">Certain (2)</option>' in out
    assert '<option value="tentative">Tentative (1)</option>' in out
    assert 'value="firm"' not in out


def test_module_options_sorted_with_counts() -> None:
    out = _html([_f("xss_check", Confidence.FIRM, "x"), _f("dir_fuzzer", Confidence.FIRM, "y")])
    assert out.index('value="dir_fuzzer"') < out.index('value="xss_check"')
    assert '<option value="xss_check">xss_check (1)</option>' in out


def test_module_names_are_escaped() -> None:
    out = _html([_f('evil"><script>x()</script>', Confidence.FIRM)])
    assert "<script>x()</script>" not in out
    assert "&lt;script&gt;" in out


def test_filter_script_checks_all_four_filters() -> None:
    out = _html([_f("a", Confidence.FIRM)])
    assert "matchesSev && matchesSearch && matchesConf && matchesMod" in out
