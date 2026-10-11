"""
VortexDAST – adapters/nuclei_adapter.py
────────────────────────────────────────────────────────────────────────────
Adapter for **nuclei** (ProjectDiscovery) — a fast, template-driven vulnerability
scanner with a large community corpus of checks (CVEs, misconfigurations,
exposures, default credentials, …).

nuclei is the highest-leverage first adapter: thousands of checks for very
little code on our side. We invoke it as a subprocess, ask it for JSON-Lines
output (``-jsonl``), and map each result into a VortexDAST :class:`Finding`.

Invocation
----------
``nuclei -u <target> -jsonl -silent`` emits one JSON object per finding on
stdout. Each object carries a rich ``info`` block (name, severity, description,
remediation, references, CVSS classification) that lines up cleanly with our
Finding model.

Licence note
------------
nuclei is MIT-licensed and invoked as a *separate program* (subprocess), so no
licence obligations flow into VortexDAST. We never import its code.

Safety
------
The target is passed as a single argv element through
:func:`core.orchestrator.run_command` (``shell=False``), so a hostile target
string cannot inject shell commands. nuclei is run in its default mode; no
templates are added that would change its request behaviour beyond its own
benign-by-default checks. **Only scan targets you are authorised to test.**
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.cvss import calculate as cvss_calc
from core.orchestrator import (
    ScanContext,
    ToolAdapter,
    parse_jsonl,
    severity_from_label,
)
from modules.base import Confidence, Finding


class NucleiAdapter(ToolAdapter):
    """Drive ``nuclei`` and map its JSONL output into Findings."""

    name: str = "nuclei"
    binary: str = "nuclei"
    description: str = (
        "Template-driven vulnerability scanner (ProjectDiscovery). Runs the "
        "community template corpus (CVEs, exposures, misconfigurations) and "
        "maps each match into a VortexDAST finding. Optional external tool."
    )
    #: nuclei can run for a while against a large template set.
    default_timeout: float = 900.0

    def build_command(self, target: str, ctx: ScanContext) -> List[str]:
        """
        Build the nuclei argv.

        ``-jsonl`` gives one JSON object per line on stdout; ``-silent``
        suppresses the banner/progress chatter so stdout is pure JSONL;
        ``-disable-update-check`` keeps the run offline-friendly and
        deterministic for CI. ``-severity`` restricts the run to
        critical/high/medium templates, since the full corpus can take tens
        of minutes against a single target.
        """
        return [
            self.binary,
            "-u",
            target,
            "-jsonl",
            "-silent",
            "-disable-update-check",
            "-severity",
            "critical,high,medium",
        ]

    def parse(self, raw_output: str) -> List[Finding]:
        """Translate nuclei JSONL into :class:`Finding` objects."""
        findings: List[Finding] = []
        for record in parse_jsonl(raw_output):
            finding = self._map_record(record)
            if finding is not None:
                findings.append(finding)
        return findings

    # ── Internal mapping ─────────────────────────────────────────────────────

    def _map_record(self, record: Dict[str, Any]) -> Optional[Finding]:
        """Map a single nuclei JSON object into a Finding (or ``None``)."""
        if not isinstance(record, dict):
            return None

        info: Dict[str, Any] = record.get("info") or {}
        template_id = record.get("template-id") or record.get("templateID") or ""

        title = info.get("name") or template_id or "nuclei finding"
        severity = severity_from_label(info.get("severity"))

        # nuclei template matches are high-signal (a template explicitly
        # matched), but not a proof-of-exploit, so FIRM rather than CERTAIN.
        confidence = Confidence.FIRM

        url = (
            record.get("matched-at")
            or record.get("matched_at")
            or record.get("host")
            or ""
        )

        cvss_vector, cvss_score = self._extract_cvss(info.get("classification") or {})

        evidence = self._build_evidence(record, template_id)

        return Finding(
            title=str(title),
            severity=severity,
            confidence=confidence,
            url=str(url),
            parameter=None,
            payload=None,
            evidence=evidence,
            description=str(info.get("description") or ""),
            remediation=str(info.get("remediation") or ""),
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            extra={
                "tool": self.name,
                "template_id": template_id,
                "type": record.get("type"),
                "host": record.get("host"),
                "matcher_name": record.get("matcher-name"),
                "extracted_results": record.get("extracted-results"),
                "tags": info.get("tags"),
                "reference": info.get("reference"),
                "cve_id": (info.get("classification") or {}).get("cve-id"),
                "cwe_id": (info.get("classification") or {}).get("cwe-id"),
                "curl_command": record.get("curl-command"),
            },
        )

    @staticmethod
    def _extract_cvss(
        classification: Dict[str, Any],
    ) -> tuple[Optional[str], Optional[float]]:
        """
        Pull the CVSS vector + score from a nuclei ``classification`` block.

        Prefers nuclei's own ``cvss-score``; when only a vector is present we
        compute the score with :func:`core.cvss.calculate` so the finding still
        carries a numeric score consistent with the rest of the report.
        """
        vector = classification.get("cvss-metrics") or None
        score = classification.get("cvss-score")

        if isinstance(score, (int, float)):
            score_val: Optional[float] = float(score)
        else:
            score_val = None

        if vector and score_val is None:
            try:
                score_val = cvss_calc(vector)
            except ValueError:
                score_val = None

        return (vector, score_val)

    @staticmethod
    def _build_evidence(record: Dict[str, Any], template_id: str) -> str:
        """Compose a concise evidence string from the most useful match fields."""
        parts: List[str] = []
        if template_id:
            parts.append(f"template={template_id}")
        matcher = record.get("matcher-name")
        if matcher:
            parts.append(f"matcher={matcher}")
        extracted = record.get("extracted-results")
        if extracted:
            parts.append(f"extracted={extracted}")
        matched = record.get("matched-at") or record.get("matched_at")
        if matched:
            parts.append(f"matched-at={matched}")
        return "; ".join(parts)
