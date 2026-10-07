"""
VortexDAST – core/issue_tracker.py
────────────────────────────────────────────────────────────────────────────
Export findings to defect trackers: GitHub Issues and Jira.

Each sufficiently-severe finding becomes one ticket. A stable marker derived
from the finding's identity is embedded in the issue body so re-runs can detect
and skip already-filed issues (best-effort deduplication via search).

Design notes
------------
*   Pure payload builders (:func:`build_github_issue`, :func:`build_jira_issue`)
    are separated from the HTTP calls so they can be unit-tested offline.
*   Credentials are never logged. Prefer environment variables
    (``GITHUB_TOKEN`` / ``JIRA_API_TOKEN``) over CLI flags.
*   Network failures never raise out of :func:`export_findings`; they are
    counted and reported so a scan is never aborted by a tracker outage.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests

from core.filters import SEVERITY_ORDER
from modules.base import Finding

logger = logging.getLogger(__name__)

_TIMEOUT_S = 15
_MARKER_PREFIX = "vortexdast-fingerprint"


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────


def finding_fingerprint(finding: Finding) -> str:
    """Stable identity for a finding across runs (title + url + parameter)."""
    basis = f"{finding.title}|{finding.url}|{finding.parameter or ''}"
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
    return f"{_MARKER_PREFIX}:{digest}"


def _severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)


def filter_by_min_severity(findings: List[Finding], min_severity: str) -> List[Finding]:
    """Keep findings at or above ``min_severity`` (SEVERITY_ORDER is high→low)."""
    threshold = _severity_rank(min_severity)
    return [f for f in findings if _severity_rank(f.severity.value) <= threshold]


def _issue_body_lines(finding: Finding) -> List[str]:
    return [
        f"**Severity:** {finding.severity.value}  |  **Confidence:** {finding.confidence.value}",
        f"**URL:** {finding.url}",
        f"**Parameter:** {finding.parameter or 'n/a'}",
        "",
        "### Description",
        finding.description or "(none)",
        "",
        "### Remediation",
        finding.remediation or "(none)",
        "",
        f"_Filed by VortexDAST — {finding_fingerprint(finding)}_",
    ]


# ─────────────────────────────────────────────────────────────────────────────
# GitHub
# ─────────────────────────────────────────────────────────────────────────────


def build_github_issue(finding: Finding) -> Dict[str, Any]:
    """Build the JSON body for a GitHub issue."""
    return {
        "title": f"[VortexDAST] {finding.title}",
        "body": "\n".join(_issue_body_lines(finding)),
        "labels": ["security", "vortexdast", f"severity:{finding.severity.value}"],
    }


def _github_issue_exists(
    session: requests.Session, repo: str, fingerprint: str
) -> bool:
    """Best-effort: search the repo for an existing issue carrying the marker."""
    try:
        resp = session.get(
            "https://api.github.com/search/issues",
            params={"q": f'repo:{repo} in:body "{fingerprint}"'},
            timeout=_TIMEOUT_S,
        )
        if resp.status_code == 200:
            return resp.json().get("total_count", 0) > 0
    except (requests.RequestException, ValueError) as exc:
        logger.debug("GitHub dedup search failed: %s", type(exc).__name__)
    return False


def create_github_issue(
    session: requests.Session, repo: str, finding: Finding
) -> Optional[int]:
    """Create one GitHub issue; returns the issue number or ``None`` on failure."""
    if _github_issue_exists(session, repo, finding_fingerprint(finding)):
        logger.info("GitHub issue already exists for %r — skipping.", finding.title)
        return None
    try:
        resp = session.post(
            f"https://api.github.com/repos/{repo}/issues",
            json=build_github_issue(finding),
            timeout=_TIMEOUT_S,
        )
    except requests.RequestException as exc:
        logger.warning("GitHub issue creation failed: %s", type(exc).__name__)
        return None
    if resp.status_code not in (200, 201):
        logger.warning("GitHub issue creation returned HTTP %d", resp.status_code)
        return None
    try:
        return int(resp.json().get("number"))
    except (ValueError, TypeError):
        return None


def github_session(token: str) -> requests.Session:
    """A requests session pre-authenticated for the GitHub API."""
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "VortexDAST",
    })
    return s


# ─────────────────────────────────────────────────────────────────────────────
# Jira
# ─────────────────────────────────────────────────────────────────────────────


def build_jira_issue(finding: Finding, project_key: str) -> Dict[str, Any]:
    """Build the JSON body for a Jira issue (API v2 plain-text description)."""
    description = "\n".join(_issue_body_lines(finding)).replace("**", "").replace("### ", "")
    return {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[VortexDAST] {finding.title}"[:255],
            "description": description,
            "issuetype": {"name": "Bug"},
            "labels": ["security", "vortexdast", f"severity-{finding.severity.value}"],
        }
    }


def create_jira_issue(
    session: requests.Session,
    base_url: str,
    project_key: str,
    finding: Finding,
) -> Optional[str]:
    """Create one Jira issue; returns the issue key (e.g. ``SEC-12``) or ``None``."""
    url = base_url.rstrip("/") + "/rest/api/2/issue"
    try:
        resp = session.post(
            url, json=build_jira_issue(finding, project_key), timeout=_TIMEOUT_S
        )
    except requests.RequestException as exc:
        logger.warning("Jira issue creation failed: %s", type(exc).__name__)
        return None
    if resp.status_code not in (200, 201):
        logger.warning("Jira issue creation returned HTTP %d", resp.status_code)
        return None
    try:
        return str(resp.json().get("key"))
    except (ValueError, TypeError):
        return None


def jira_session(email: str, token: str) -> requests.Session:
    """A requests session using Jira Basic auth (email + API token)."""
    s = requests.Session()
    s.auth = (email, token)
    s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
    return s


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class ExportResult:
    """Outcome of an issue-export run."""

    created: List[str] = field(default_factory=list)
    skipped: int = 0
    failed: int = 0

    @property
    def total_created(self) -> int:
        return len(self.created)


def export_to_github(
    session: requests.Session,
    repo: str,
    findings: List[Finding],
    min_severity: str = "high",
) -> ExportResult:
    """Create GitHub issues for findings at or above ``min_severity``."""
    result = ExportResult()
    for finding in filter_by_min_severity(findings, min_severity):
        number = create_github_issue(session, repo, finding)
        if number is None:
            result.failed += 1
        else:
            result.created.append(f"#{number}")
    return result


def export_to_jira(
    session: requests.Session,
    base_url: str,
    project_key: str,
    findings: List[Finding],
    min_severity: str = "high",
) -> ExportResult:
    """Create Jira issues for findings at or above ``min_severity``."""
    result = ExportResult()
    for finding in filter_by_min_severity(findings, min_severity):
        key = create_jira_issue(session, base_url, project_key, finding)
        if key is None:
            result.failed += 1
        else:
            result.created.append(key)
    return result
