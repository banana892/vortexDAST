"""
VortexDAST – modules/base.py
────────────────────────────────────────────────────────────────────────────
Abstract base class for all VortexDAST scanning modules.

Every vulnerability scanner module (XSS, SQLi, SSRF, headers audit, …) must
subclass :class:`BaseScannerModule` and implement :meth:`run`.  This ensures
a uniform interface so the CLI orchestrator can discover and invoke modules
without knowing their internals.

The dataclasses defined here (:class:`Finding`, :class:`Severity`) form the
shared vocabulary for all scan results, feeding directly into the report
generator.
"""

from __future__ import annotations

import abc
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.crawler import CrawledEndpoint
from core.requester import Requester


# ─────────────────────────────────────────────────────────────────────────────
# Shared result types
# ─────────────────────────────────────────────────────────────────────────────


class Severity(str, Enum):
    """CVSS-aligned severity levels used across all findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(str, Enum):
    """How strongly the observed evidence supports the finding."""

    CERTAIN = "certain"
    """Directly observed (e.g. a missing header, leaked file contents)."""

    FIRM = "firm"
    """Strong signal not present in the baseline (e.g. new DBMS error, raw reflection)."""

    TENTATIVE = "tentative"
    """Heuristic signal that needs manual verification (e.g. HTTP 500, timing, length delta)."""


CONFIDENCE_ORDER: List[str] = [c.value for c in Confidence]


@dataclass
class Finding:
    """
    A single discovered vulnerability or security weakness.

    Attributes are designed to map directly to JSON report output and to carry
    enough context for a developer to reproduce and remediate the issue.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    """Unique finding ID (UUID4) for deduplication and cross-referencing."""

    title: str = ""
    """Short, human-readable name of the vulnerability (e.g. 'Reflected XSS')."""

    severity: Severity = Severity.INFORMATIONAL
    """CVSS-aligned severity rating."""

    confidence: Confidence = Confidence.FIRM
    """How strongly the evidence supports this finding."""

    url: str = ""
    """The endpoint URL where the vulnerability was observed."""

    parameter: Optional[str] = None
    """The specific HTTP parameter that triggered the finding (if applicable)."""

    payload: Optional[str] = None
    """The probe / payload that triggered the finding (if applicable)."""

    evidence: str = ""
    """Snippet of the response body or headers that confirms the finding."""

    description: str = ""
    """Detailed explanation of the vulnerability."""

    remediation: str = ""
    """Recommended remediation steps."""

    extra: Dict[str, Any] = field(default_factory=dict)
    """Module-specific metadata (e.g. matched regex pattern, response diff)."""

    cvss_vector: Optional[str] = None
    """
    CVSS v3.1 vector string calculated for this specific finding.
    Example: ``"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"``
    Set by each scanner module at Finding creation time via :mod:`core.cvss`.
    """

    cvss_score: Optional[float] = None
    """
    Calculated CVSS v3.1 base score (0.0 – 10.0).
    Derived from :attr:`cvss_vector` using the official FIRST.org formula.
    """

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the finding to a plain dict for JSON reporting."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "extra": self.extra,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Abstract base module
# ─────────────────────────────────────────────────────────────────────────────


class BaseScannerModule(abc.ABC):
    """
    Abstract base class for all VortexDAST vulnerability scanning modules.

    Subclasses must implement :meth:`run`, which receives a single
    :class:`~core.crawler.CrawledEndpoint` and returns a (possibly empty)
    list of :class:`Finding` objects.

    The ``name`` and ``description`` class attributes identify the module in
    CLI output and scan reports.

    Parameters
    ----------
    requester : Requester
        Shared HTTP session.  Modules *must not* create their own sessions;
        they must reuse the one passed in to honour rate-limiting globally.

    Example
    -------
    >>> class MyModule(BaseScannerModule):
    ...     name = "my_check"
    ...     description = "Checks for something interesting."
    ...
    ...     def run(self, endpoint):
    ...         findings = []
    ...         # … scanning logic …
    ...         return findings
    """

    #: Short machine-readable identifier for this module (override in subclass).
    name: str = "base"

    #: Human-readable description shown in the CLI module list.
    description: str = "Base scanner module — not intended for direct use."

    def __init__(self, requester: Requester) -> None:
        self.requester = requester

    @abc.abstractmethod
    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        """
        Execute this module against a single crawled endpoint.

        Parameters
        ----------
        endpoint : CrawledEndpoint
            The crawled page including its URL, forms, links, and response
            headers.

        Returns
        -------
        list[Finding]
            Zero or more findings discovered on this endpoint.
        """

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r})"
