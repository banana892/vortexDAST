"""
VortexDAST – core/filters.py
Severity / confidence thresholds and YAML suppression rules for findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Pattern, Tuple

import yaml

from modules.base import CONFIDENCE_ORDER, Finding

SEVERITY_ORDER: List[str] = ["critical", "high", "medium", "low", "informational"]

_EXACT_KEYS = ("module", "severity", "confidence")
_REGEX_KEYS = ("title", "url", "parameter")
_ALLOWED_KEYS = set(_EXACT_KEYS) | set(_REGEX_KEYS) | {"reason"}


class FilterConfigError(ValueError):
    """Raised for an invalid suppression file or threshold value."""


@dataclass
class SuppressionRule:
    exact: Dict[str, str] = field(default_factory=dict)
    patterns: Dict[str, Pattern[str]] = field(default_factory=dict)
    reason: str = ""

    def matches(self, finding: Finding) -> bool:
        values = _finding_fields(finding)
        if any(values[k] != v for k, v in self.exact.items()):
            return False
        return all(p.search(values[k]) for k, p in self.patterns.items())


def _finding_fields(finding: Finding) -> Dict[str, str]:
    extra = finding.extra if isinstance(finding.extra, dict) else {}
    return {
        "module": str(extra.get("module", "")),
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "title": finding.title or "",
        "url": finding.url or "",
        "parameter": finding.parameter or "",
    }


def _parse_rule(raw: Any, index: int) -> SuppressionRule:
    where = f"suppression rule #{index + 1}"
    if not isinstance(raw, dict):
        raise FilterConfigError(f"{where}: expected a mapping, got {type(raw).__name__}")

    unknown = set(raw) - _ALLOWED_KEYS
    if unknown:
        raise FilterConfigError(
            f"{where}: unknown key(s) {sorted(unknown)}; allowed: {sorted(_ALLOWED_KEYS)}"
        )
    if not any(k in raw for k in (*_EXACT_KEYS, *_REGEX_KEYS)):
        # A rule with no match criteria would silently suppress every finding.
        raise FilterConfigError(f"{where}: must specify at least one match field")

    rule = SuppressionRule(reason=str(raw.get("reason", "")))
    for key in _EXACT_KEYS:
        if key in raw:
            rule.exact[key] = str(raw[key]).lower()
    for key in _REGEX_KEYS:
        if key in raw:
            try:
                rule.patterns[key] = re.compile(str(raw[key]))
            except re.error as exc:
                raise FilterConfigError(f"{where}: invalid regex for {key!r}: {exc}") from exc
    return rule


def load_suppression_rules(path: str) -> List[SuppressionRule]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except OSError as exc:
        raise FilterConfigError(f"cannot read suppression file {path!r}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise FilterConfigError(f"invalid YAML in suppression file {path!r}: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("suppress", []), list):
        raise FilterConfigError(f"{path!r}: expected a top-level 'suppress:' list")
    return [_parse_rule(r, i) for i, r in enumerate(data.get("suppress", []))]


class FindingFilter:
    """Drops findings below severity/confidence thresholds or matching a suppression rule."""

    def __init__(
        self,
        min_severity: Optional[str] = None,
        min_confidence: Optional[str] = None,
        rules: Optional[List[SuppressionRule]] = None,
    ) -> None:
        if min_severity is not None and min_severity not in SEVERITY_ORDER:
            raise FilterConfigError(f"invalid severity {min_severity!r}; choose from {SEVERITY_ORDER}")
        if min_confidence is not None and min_confidence not in CONFIDENCE_ORDER:
            raise FilterConfigError(
                f"invalid confidence {min_confidence!r}; choose from {CONFIDENCE_ORDER}"
            )
        self.min_severity = min_severity
        self.min_confidence = min_confidence
        self.rules = rules or []

    def _reject_reason(self, finding: Finding) -> Optional[str]:
        if self.min_severity and (
            SEVERITY_ORDER.index(finding.severity.value) > SEVERITY_ORDER.index(self.min_severity)
        ):
            return f"below --min-severity {self.min_severity}"
        if self.min_confidence and (
            CONFIDENCE_ORDER.index(finding.confidence.value)
            > CONFIDENCE_ORDER.index(self.min_confidence)
        ):
            return f"below --min-confidence {self.min_confidence}"
        for rule in self.rules:
            if rule.matches(finding):
                return f"suppression rule: {rule.reason}" if rule.reason else "suppression rule"
        return None

    def apply(self, findings: List[Finding]) -> Tuple[List[Finding], List[Tuple[Finding, str]]]:
        """Return (kept findings, [(dropped finding, reason), ...])."""
        kept: List[Finding] = []
        dropped: List[Tuple[Finding, str]] = []
        for finding in findings:
            reason = self._reject_reason(finding)
            if reason is None:
                kept.append(finding)
            else:
                dropped.append((finding, reason))
        return kept, dropped
