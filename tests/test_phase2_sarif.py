"""
VortexDAST – tests/test_phase2_sarif.py
SARIF 2.1.0 export: schema validity, rule grouping, severity mapping, file dispatch.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.reporter import Reporter, _sarif_rule_id
from modules.base import Confidence, Finding, Severity

jsonschema = pytest.importorskip("jsonschema")

_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "sarif-2.1.0.schema.json")


def _f(title: str, module: str, **kw: Any) -> Finding:
    kw.setdefault("url", "https://t.com/")
    return Finding(title=title, extra={"module": module}, **kw)


def _findings() -> list:
    return [
        _f("Exposed Configuration File: /.env", "dir_fuzzer", severity=Severity.HIGH,
           confidence=Confidence.CERTAIN, url="https://t.com/.env", parameter="/.env",
           evidence="DB_PASSWORD=x", cvss_score=7.5),
        _f("Exposed Configuration File: /config.bak", "dir_fuzzer", severity=Severity.MEDIUM,
           url="https://t.com/config.bak", cvss_score=5.3),
        _f("SQL Injection — MySQL Error Signature Detected", "sqli_check", severity=Severity.HIGH,
           url="https://t.com/p?id=1", parameter="id", payload="'"),
        _f("Missing Referrer-Policy Header", "headers_audit", severity=Severity.INFORMATIONAL,
           confidence=Confidence.CERTAIN, cvss_score=0.0),
    ]


def _sarif(findings: list) -> dict:
    return Reporter(findings, "https://t.com", scan_meta={"threads": 10}, console=MagicMock()).to_sarif()


def test_output_validates_against_sarif_schema() -> None:
    with open(_SCHEMA_PATH, encoding="utf-8") as fh:
        jsonschema.validate(_sarif(_findings()), json.load(fh))


def test_empty_scan_is_valid_sarif() -> None:
    with open(_SCHEMA_PATH, encoding="utf-8") as fh:
        doc = _sarif([])
        jsonschema.validate(doc, json.load(fh))
    assert doc["runs"][0]["results"] == []


def test_rule_id_strips_per_instance_suffix() -> None:
    assert _sarif_rule_id(_findings()[0]) == "dir_fuzzer/exposed-configuration-file"
    assert _sarif_rule_id(_findings()[2]) == "sqli_check/sql-injection"


def test_instances_share_rule_with_highest_security_severity() -> None:
    rules = {r["id"]: r for r in _sarif(_findings())["runs"][0]["tool"]["driver"]["rules"]}
    assert len(rules) == 3
    assert rules["dir_fuzzer/exposed-configuration-file"]["properties"]["security-severity"] == "7.5"


def test_missing_cvss_falls_back_to_severity_bucket() -> None:
    rules = {r["id"]: r for r in _sarif(_findings())["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["sqli_check/sql-injection"]["properties"]["security-severity"] == "8.1"
    assert "security-severity" not in rules["headers_audit/missing-referrer-policy-header"]["properties"]


def test_levels_and_result_properties() -> None:
    results = _sarif(_findings())["runs"][0]["results"]
    assert [r["level"] for r in results] == ["error", "warning", "error", "note"]
    assert results[0]["properties"]["confidence"] == "certain"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://t.com/.env"
    assert "parameter: id" in results[2]["message"]["text"]


def test_fingerprints_stable_across_runs_and_distinct_per_finding() -> None:
    a = [r["partialFingerprints"]["vortexdast/v1"] for r in _sarif(_findings())["runs"][0]["results"]]
    b = [r["partialFingerprints"]["vortexdast/v1"] for r in _sarif(_findings())["runs"][0]["results"]]
    assert a == b
    assert len(set(a)) == len(a)


@pytest.mark.parametrize("name", ["report.sarif", "report.sarif.json", "REPORT.SARIF"])
def test_save_dispatches_sarif_by_extension(tmp_path: Any, name: str) -> None:
    path = tmp_path / name
    Reporter(_findings(), "https://t.com", console=MagicMock()).save(str(path))
    assert json.loads(path.read_text())["version"] == "2.1.0"


def test_plain_json_still_uses_native_format(tmp_path: Any) -> None:
    path = tmp_path / "report.json"
    Reporter(_findings(), "https://t.com", console=MagicMock()).save(str(path))
    assert "vortexdast_version" in json.loads(path.read_text())
