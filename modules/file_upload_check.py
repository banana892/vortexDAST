"""
VortexDAST – modules/file_upload_check.py
────────────────────────────────────────────────────────────────────────────
Unrestricted File Upload detection module (OWASP A04:2021 / CWE-434).

Detection Strategy
------------------
For every ``multipart/form-data`` form carrying a file input, uploads a
short, uniquely-marked, inert text body under each of a handful of
dangerous extensions (``.php``, ``.jsp``, ``.asp``, ``.aspx``, ``.svg``,
``.html``, …) with its ``Content-Type`` spoofed as ``image/jpeg`` — the
classic bypass for a validator that checks the client-supplied
Content-Type (or nothing at all) rather than the file's actual content.

*   **Accepted** (HTTP < 400, no rejection-indicator string in the body)
    → ``MEDIUM``/``TENTATIVE``: the dangerous extension was not rejected,
    but we don't yet know if it landed anywhere web-reachable.
*   **Accepted *and* retrievable** — the response reveals a path/URL to the
    stored file (its filename appears inside a quoted attribute), and
    fetching that URL back returns our own marker text
    → ``HIGH``/``FIRM``: the file is confirmed stored under a web-reachable
    path with its dangerous extension intact — the precondition for
    execution if the server (or a misconfigured handler) ever interprets
    it as code.

Safety
------
The uploaded content is always inert, clearly-marked plain text — never
executable payload content — and execution is never attempted, requested,
or triggered. Retrieval only re-fetches the exact bytes VortexDAST itself
uploaded, to confirm storage, not to run anything.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint
from core.cvss import build_vector, calculate as cvss_calc
from core.parser import ParsedForm

logger = logging.getLogger(__name__)

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_FILE_UPLOAD_PATH = os.path.join(_PAYLOADS_DIR, "file_upload_probes.json")

# Spoofed Content-Type — the classic bypass for a validator that checks only
# the client-supplied MIME type.
_SPOOFED_CONTENT_TYPE = "image/jpeg"

# Volume cap: same shape as every other adapter/module's own cap
# (e.g. interactsh's _MAX_PROBES, json_fuzz's DEFAULT_MAX_LEAVES).
_MAX_EXTENSIONS_PER_FORM = 5

# Accepted, unconfirmed whether it's web-reachable.
# AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:L / A:N
_CVSS_VECTOR_ACCEPTED = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="L", A="N"
)
_CVSS_SCORE_ACCEPTED: float = cvss_calc(_CVSS_VECTOR_ACCEPTED)

# Confirmed stored at a web-reachable path — scope changes once a new,
# server-hosted artifact exists under attacker control.
# AV:N / AC:L / PR:N / UI:N / S:C / C:N / I:H / A:N
_CVSS_VECTOR_STORED = build_vector(
    AV="N", AC="L", PR="N", UI="N", S="C", C="N", I="H", A="N"
)
_CVSS_SCORE_STORED: float = cvss_calc(_CVSS_VECTOR_STORED)


class FileUploadCheckModule(BaseScannerModule):
    """Unrestricted file-upload detection via dangerous-extension probing."""

    name: str = "file_upload_check"
    description: str = (
        "Detects unrestricted file upload by submitting a benign file under "
        "dangerous extensions (.php/.jsp/.asp/.svg/…) with a spoofed image "
        "Content-Type, and checking whether it's accepted and retrievable."
    )

    def __init__(self, requester: Any, payloads_path: Optional[str] = None) -> None:
        super().__init__(requester)
        path = payloads_path or _FILE_UPLOAD_PATH
        self._extensions, self._rejection_indicators = _load_file_upload_probes(path)

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        findings: List[Finding] = []
        if not self._extensions:
            logger.warning("file_upload_check: no probes loaded — skipping %s", endpoint.url)
            return findings

        for form in endpoint.forms:
            file_field_name = _file_field_name(form)
            if file_field_name is None:
                continue
            findings.extend(self._probe_form(form, file_field_name))

        return findings

    def _probe_form(self, form: ParsedForm, file_field_name: str) -> List[Finding]:
        findings: List[Finding] = []
        other_fields = {
            f.name: f.default_value for f in form.fields if f.field_type != "file" and f.name
        }

        for ext_probe in self._extensions[:_MAX_EXTENSIONS_PER_FORM]:
            marker = f"VortexDAST file-upload probe {uuid.uuid4().hex} - inert text, not executable."
            filename = f"vortexdast_probe{ext_probe['extension']}"

            resp, err = self.requester.post(
                form.action_url,
                data=other_fields,
                files={file_field_name: (filename, marker.encode("utf-8"), _SPOOFED_CONTENT_TYPE)},
            )
            if err or resp is None or resp.status_code >= 400:
                continue
            body = resp.text or ""
            if self._looks_rejected(body):
                continue

            findings.append(self._evaluate_accepted(form.action_url, filename, ext_probe, body, marker))

        return findings

    def _looks_rejected(self, body: str) -> bool:
        lower = body.lower()
        return any(indicator in lower for indicator in self._rejection_indicators)

    def _evaluate_accepted(
        self, action_url: str, filename: str, ext_probe: Dict[str, str], body: str, marker: str
    ) -> Finding:
        stored_url = self._find_stored_url(action_url, filename, body)
        if stored_url is not None:
            fetch_resp, fetch_err = self.requester.get(stored_url)
            if (
                not fetch_err
                and fetch_resp is not None
                and fetch_resp.status_code == 200
                and marker in (fetch_resp.text or "")
            ):
                return self._stored_finding(action_url, stored_url, filename, ext_probe)
        return self._accepted_finding(action_url, filename, ext_probe)

    @staticmethod
    def _find_stored_url(action_url: str, filename: str, body: str) -> Optional[str]:
        match = re.search(r'["\']([^"\']*' + re.escape(filename) + r')["\']', body)
        if not match:
            return None
        candidate = match.group(1)
        return candidate if candidate.lower().startswith("http") else urljoin(action_url, candidate)

    def _accepted_finding(self, action_url: str, filename: str, ext_probe: Dict[str, str]) -> Finding:
        logger.info("⚡ File Upload (accepted): %s | file=%s", action_url, filename)
        return Finding(
            title="Unrestricted File Upload — Dangerous Extension Accepted",
            severity=Severity.MEDIUM,
            confidence=Confidence.TENTATIVE,
            url=action_url,
            parameter=None,
            payload=filename,
            evidence=(
                f"Uploading '{filename}' with Content-Type '{_SPOOFED_CONTENT_TYPE}' "
                "was accepted — no rejection indicator appeared in the response."
            ),
            description=(
                f"The upload form at '{action_url}' accepted a file named "
                f"'{filename}' ({ext_probe['description']}) sent with a "
                f"spoofed '{_SPOOFED_CONTENT_TYPE}' Content-Type. The server "
                "did not reject the dangerous extension, suggesting upload "
                "validation checks only the client-supplied Content-Type (or "
                "nothing at all) rather than the file's actual content. "
                "Execution was not attempted — the uploaded content is inert "
                "text, and no web-reachable path for it was found in the "
                "response."
            ),
            remediation=(
                "Validate uploads by content (magic bytes), not by "
                "client-supplied Content-Type or filename extension. Store "
                "uploads outside the web root under a randomised name, and "
                "serve them through a handler that never interprets them as "
                "code."
            ),
            cvss_vector=_CVSS_VECTOR_ACCEPTED,
            cvss_score=_CVSS_SCORE_ACCEPTED,
            extra={"extension": ext_probe["extension"], "filename": filename, "module": self.name},
        )

    def _stored_finding(
        self, action_url: str, stored_url: str, filename: str, ext_probe: Dict[str, str]
    ) -> Finding:
        logger.info("⚡ File Upload (stored+retrievable): %s | url=%s", action_url, stored_url)
        return Finding(
            title="Unrestricted File Upload — Dangerous File Stored and Retrievable",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=action_url,
            parameter=None,
            payload=filename,
            evidence=(
                f"Uploaded '{filename}' and retrieved the exact same marker "
                f"content back from '{stored_url}'."
            ),
            description=(
                f"The upload form at '{action_url}' accepted '{filename}' "
                f"({ext_probe['description']}), and the uploaded content was "
                f"confirmed retrievable at '{stored_url}' — the file is "
                "stored under a web-reachable path with its dangerous "
                "extension intact. Execution was not attempted; retrieval "
                "alone confirms the file is hosted, which is the "
                "precondition for this extension to execute if the server "
                "(or a misconfigured handler) ever interprets it as code."
            ),
            remediation=(
                "Validate uploads by content (magic bytes), not Content-Type "
                "or extension. Store uploads outside the web root under a "
                "randomised name, and serve them through a handler that never "
                "interprets them as code (or set Content-Disposition: "
                "attachment on the serving route)."
            ),
            cvss_vector=_CVSS_VECTOR_STORED,
            cvss_score=_CVSS_SCORE_STORED,
            extra={
                "extension": ext_probe["extension"],
                "filename": filename,
                "stored_url": stored_url,
                "module": self.name,
            },
        )


# ─────────────────────────────────────────────────────────────────────────────
# Module-level helpers
# ─────────────────────────────────────────────────────────────────────────────


def _file_field_name(form: ParsedForm) -> Optional[str]:
    if "multipart" not in form.enctype.lower():
        return None
    return next((f.name for f in form.fields if f.field_type == "file" and f.name), None)


def _load_file_upload_probes(path: str) -> Tuple[List[Dict[str, str]], Set[str]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.error("file_upload_probes.json not found at %s", path)
        return [], set()
    except json.JSONDecodeError as exc:
        logger.error("file_upload_probes.json parse error: %s", exc)
        return [], set()

    extensions: List[Dict[str, str]] = data.get("dangerous_extensions", [])
    rejection_indicators = {s.lower() for s in data.get("rejection_indicators", [])}

    logger.debug(
        "file_upload_check: loaded %d extensions, %d rejection indicators from %s",
        len(extensions), len(rejection_indicators), path,
    )
    return extensions, rejection_indicators
