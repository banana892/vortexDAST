"""
VortexDAST – tests/test_missing_vuln_classes.py
────────────────────────────────────────────────────────────────────────────
Unit tests for the §5 item 5 "missing vuln classes" native modules:
command_injection_check, open_redirect_check, cors_check, file_upload_check.

All network calls are mocked via unittest.mock so tests run offline.
"""

from __future__ import annotations

import os
import sys
from datetime import timedelta
from typing import Dict, List, Optional
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crawler import CrawledEndpoint
from core.parser import FormField, ParsedForm, ParsedLink
from modules.base import Confidence, Severity
from modules.command_injection_check import CommandInjectionCheckModule
from modules.cors_check import CORSCheckModule
from modules.file_upload_check import FileUploadCheckModule
from modules.open_redirect_check import OpenRedirectCheckModule
from scanner import MODULE_REGISTRY

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_CMDI_PATH = os.path.join(_PAYLOADS_DIR, "command_injection_probes.json")
_OR_PATH = os.path.join(_PAYLOADS_DIR, "open_redirect_probes.json")
_UPLOAD_PATH = os.path.join(_PAYLOADS_DIR, "file_upload_probes.json")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _requester() -> MagicMock:
    return MagicMock()


def _resp(
    text: str = "",
    status: int = 200,
    elapsed: float = 0.05,
    headers: Optional[Dict[str, str]] = None,
    history: Optional[list] = None,
    url: str = "",
) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.content = text.encode("utf-8")
    r.headers = headers or {}
    r.elapsed = timedelta(seconds=elapsed)
    r.history = history or []
    r.url = url
    return r


def _endpoint(
    url: str = "https://t.com/page",
    query_params: Optional[Dict[str, List[str]]] = None,
    forms: Optional[List[ParsedForm]] = None,
    links: Optional[List[ParsedLink]] = None,
) -> CrawledEndpoint:
    return CrawledEndpoint(
        url=url,
        status_code=200,
        depth=0,
        response_headers={},
        query_params=query_params or {},
        forms=forms or [],
        links=links or [],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Command Injection
# ─────────────────────────────────────────────────────────────────────────────


class TestCommandInjectionCheck:
    def _module(self) -> CommandInjectionCheckModule:
        return CommandInjectionCheckModule(_requester(), payloads_path=_CMDI_PATH)

    def test_module_name(self) -> None:
        assert self._module().name == "command_injection_check"
        assert "command injection" in self._module().description.lower()

    def test_registered(self) -> None:
        assert MODULE_REGISTRY["command_injection_check"] is CommandInjectionCheckModule

    def test_no_probes_loaded_returns_empty(self) -> None:
        module = CommandInjectionCheckModule(_requester(), payloads_path="/nonexistent.json")
        assert module.run(_endpoint(query_params={"q": ["x"]})) == []

    def test_output_based_hit_reported(self) -> None:
        module = self._module()
        baseline = _resp("normal page")
        injected = _resp("normal page uid=0(root) gid=0(root)")

        def fake_get(url: str, **kwargs):
            if "id" in url and ("%3B" in url or ";" in url or "|" in url or "&" in url or "$" in url or "`" in url):
                return (injected, None)
            return (baseline, None)

        module.requester.get.side_effect = fake_get
        findings = module.run(_endpoint(query_params={"q": ["x"]}))

        hits = [f for f in findings if "Captured Output" in f.title]
        assert len(hits) >= 1
        assert hits[0].severity == Severity.HIGH
        assert hits[0].confidence == Confidence.FIRM

    def test_output_marker_already_in_baseline_not_reported(self) -> None:
        """A page that naturally prints uid=/gid= text must not false-positive."""
        module = self._module()
        same = _resp("account page uid=1000 gid=1000")
        module.requester.get.return_value = (same, None)
        findings = module.run(_endpoint(query_params={"q": ["x"]}))
        assert [f for f in findings if "Captured Output" in f.title] == []

    def test_time_based_blind_detected(self) -> None:
        module = self._module()
        baseline = _resp("ok", elapsed=0.05)
        delayed = _resp("ok", elapsed=4.5)

        def fake_get(url: str, **kwargs):
            if "sleep" in url:
                return (delayed, None)
            return (baseline, None)

        module.requester.get.side_effect = fake_get
        findings = module.run(_endpoint(query_params={"q": ["x"]}))

        hits = [f for f in findings if "Time-Based" in f.title]
        assert len(hits) == 1
        assert hits[0].severity == Severity.HIGH
        assert hits[0].confidence == Confidence.FIRM

    def test_time_based_requires_reproduction(self) -> None:
        module = self._module()
        baseline = _resp("ok", elapsed=0.05)
        slow_once = _resp("ok", elapsed=4.5)
        fast_confirm = _resp("ok", elapsed=0.06)
        calls = {"n": 0}

        def fake_get(url: str, **kwargs):
            if "sleep" in url:
                calls["n"] += 1
                return (slow_once, None) if calls["n"] == 1 else (fast_confirm, None)
            return (baseline, None)

        module.requester.get.side_effect = fake_get
        findings = module.run(_endpoint(query_params={"q": ["x"]}))
        assert [f for f in findings if "Time-Based" in f.title] == []

    def test_post_form_output_based_hit(self) -> None:
        module = self._module()
        baseline = _resp("ok")
        injected = _resp("ok uid=0(root) gid=0(root)")

        def fake_post(url: str, data=None, **kwargs):
            value = (data or {}).get("name", "")
            if any(ch in value for ch in (";", "|", "&", "$", "`")):
                return (injected, None)
            return (baseline, None)

        module.requester.post.side_effect = fake_post
        form = ParsedForm(
            action_url="https://t.com/submit",
            method="POST",
            fields=[FormField(name="name", field_type="text", default_value="bob")],
        )
        findings = module.run(_endpoint(forms=[form]))
        assert any("Captured Output" in f.title for f in findings)


# ─────────────────────────────────────────────────────────────────────────────
# Open Redirect
# ─────────────────────────────────────────────────────────────────────────────


class TestOpenRedirectCheck:
    def _module(self) -> OpenRedirectCheckModule:
        return OpenRedirectCheckModule(_requester(), payloads_path=_OR_PATH)

    def test_module_name(self) -> None:
        assert self._module().name == "open_redirect_check"

    def test_registered(self) -> None:
        assert MODULE_REGISTRY["open_redirect_check"] is OpenRedirectCheckModule

    def test_confirmed_redirect_to_canary_reported(self) -> None:
        module = self._module()

        def fake_get(url: str, **kwargs):
            if "canary" in url:
                return (
                    _resp(
                        "",
                        status=302,
                        headers={"Location": "https://vortexdast-redirect-canary.invalid/"},
                    ),
                    None,
                )
            return (_resp(""), None)

        module.requester.get.side_effect = fake_get
        findings = module.run(_endpoint(query_params={"next": ["https://t.com/home"]}))

        hits = [f for f in findings if "Confirmed" in f.title]
        assert len(hits) == 1
        assert hits[0].severity == Severity.MEDIUM
        assert hits[0].confidence == Confidence.CERTAIN
        assert hits[0].parameter == "next"

    def test_redirect_to_own_host_not_reported(self) -> None:
        module = self._module()
        # Server rejects/normalises the off-site value and bounces to its own login.
        module.requester.get.return_value = (
            _resp("", status=302, headers={"Location": "https://t.com/login"}), None
        )
        findings = module.run(_endpoint(query_params={"next": ["https://t.com/home"]}))
        assert findings == []

    def test_non_candidate_param_skipped(self) -> None:
        module = self._module()
        module.requester.get.return_value = (
            _resp("", status=302, headers={"Location": "https://vortexdast-redirect-canary.invalid/"}),
            None,
        )
        # "q" is not a redirect-indicative parameter name.
        findings = module.run(_endpoint(query_params={"q": ["search term"]}))
        assert findings == []

    def test_js_redirect_pattern_heuristic_reported(self) -> None:
        module = self._module()

        def fake_get(url: str, **kwargs):
            if "canary" in url:
                body = '<script>window.location="https://vortexdast-redirect-canary.invalid/";</script>'
                return (_resp(body, status=200), None)
            return (_resp("home page", status=200), None)

        module.requester.get.side_effect = fake_get
        findings = module.run(_endpoint(query_params={"redirect": ["https://t.com/home"]}))

        hits = [f for f in findings if "Client-Side" in f.title]
        assert len(hits) == 1
        assert hits[0].severity == Severity.LOW
        assert hits[0].confidence == Confidence.TENTATIVE

    def test_userinfo_bypass_probe_built_from_endpoint_host(self) -> None:
        module = self._module()
        probes = module._probes_for("https://t.com/redirect")
        assert any("t.com@vortexdast-redirect-canary.invalid" in p["value"] for p in probes)


# ─────────────────────────────────────────────────────────────────────────────
# CORS
# ─────────────────────────────────────────────────────────────────────────────


class TestCORSCheck:
    def _module(self) -> CORSCheckModule:
        return CORSCheckModule(_requester())

    def test_module_name(self) -> None:
        assert self._module().name == "cors_check"

    def test_registered(self) -> None:
        assert MODULE_REGISTRY["cors_check"] is CORSCheckModule

    def test_credentialed_reflection_is_high(self) -> None:
        module = self._module()

        def fake_get(url: str, headers=None, **kwargs):
            origin = (headers or {}).get("Origin", "")
            if origin == "null":
                return (_resp(""), None)
            return (
                _resp(
                    "",
                    headers={
                        "Access-Control-Allow-Origin": origin,
                        "Access-Control-Allow-Credentials": "true",
                    },
                ),
                None,
            )

        module.requester.get.side_effect = fake_get
        findings = module.run(_endpoint())

        hits = [f for f in findings if f.severity == Severity.HIGH]
        assert len(hits) == 1
        assert hits[0].confidence == Confidence.CERTAIN
        assert "vortexdast-cors-attacker.invalid" in hits[0].evidence

    def test_wildcard_with_credentials_is_high(self) -> None:
        module = self._module()
        module.requester.get.return_value = (
            _resp("", headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}),
            None,
        )
        findings = module.run(_endpoint())
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_reflection_without_credentials_is_medium_tentative(self) -> None:
        module = self._module()

        def fake_get(url: str, headers=None, **kwargs):
            origin = (headers or {}).get("Origin", "")
            return (_resp("", headers={"Access-Control-Allow-Origin": origin}), None)

        module.requester.get.side_effect = fake_get
        findings = module.run(_endpoint())
        assert len(findings) >= 1
        assert all(f.severity == Severity.MEDIUM and f.confidence == Confidence.TENTATIVE for f in findings)

    def test_fixed_allowlisted_origin_not_reported(self) -> None:
        module = self._module()
        module.requester.get.return_value = (
            _resp("", headers={"Access-Control-Allow-Origin": "https://trusted-partner.example"}),
            None,
        )
        findings = module.run(_endpoint())
        assert findings == []

    def test_no_cors_headers_not_reported(self) -> None:
        module = self._module()
        module.requester.get.return_value = (_resp(""), None)
        findings = module.run(_endpoint())
        assert findings == []

    def test_dedup_runs_once_per_path(self) -> None:
        module = self._module()
        module.requester.get.return_value = (
            _resp("", headers={"Access-Control-Allow-Origin": "https://trusted.example"}), None
        )
        module.run(_endpoint(url="https://t.com/api"))
        calls_after_first = module.requester.get.call_count
        module.run(_endpoint(url="https://t.com/api"))  # same origin+path again
        assert module.requester.get.call_count == calls_after_first


# ─────────────────────────────────────────────────────────────────────────────
# File Upload
# ─────────────────────────────────────────────────────────────────────────────


class TestFileUploadCheck:
    def _module(self) -> FileUploadCheckModule:
        return FileUploadCheckModule(_requester(), payloads_path=_UPLOAD_PATH)

    def _upload_form(self) -> ParsedForm:
        return ParsedForm(
            action_url="https://t.com/upload",
            method="POST",
            fields=[FormField(name="avatar", field_type="file", default_value="")],
            enctype="multipart/form-data",
        )

    def test_module_name(self) -> None:
        assert self._module().name == "file_upload_check"

    def test_registered(self) -> None:
        assert MODULE_REGISTRY["file_upload_check"] is FileUploadCheckModule

    def test_non_multipart_form_skipped(self) -> None:
        module = self._module()
        form = ParsedForm(
            action_url="https://t.com/upload",
            method="POST",
            fields=[FormField(name="avatar", field_type="file", default_value="")],
        )  # default enctype is urlencoded, not multipart
        findings = module.run(_endpoint(forms=[form]))
        assert findings == []
        module.requester.post.assert_not_called()

    def test_no_file_field_skipped(self) -> None:
        module = self._module()
        form = ParsedForm(
            action_url="https://t.com/upload",
            method="POST",
            fields=[FormField(name="comment", field_type="text", default_value="")],
            enctype="multipart/form-data",
        )
        findings = module.run(_endpoint(forms=[form]))
        assert findings == []

    def test_accepted_extension_reported(self) -> None:
        module = self._module()
        module.requester.post.return_value = (_resp("Upload complete!", status=200), None)
        findings = module.run(_endpoint(forms=[self._upload_form()]))

        hits = [f for f in findings if "Accepted" in f.title]
        assert len(hits) >= 1
        assert hits[0].severity == Severity.MEDIUM
        assert hits[0].confidence == Confidence.TENTATIVE

    def test_rejected_extension_not_reported(self) -> None:
        module = self._module()
        module.requester.post.return_value = (
            _resp("Error: invalid file extension", status=200), None
        )
        findings = module.run(_endpoint(forms=[self._upload_form()]))
        assert findings == []

    def test_stored_and_retrievable_upgrades_to_high(self) -> None:
        module = self._module()
        state: Dict[str, str] = {}

        def fake_post(url: str, data=None, files=None, **kwargs):
            filename, content, _ctype = next(iter(files.values()))
            state["marker"] = content.decode()
            state["url"] = f"https://t.com/uploads/{filename}"
            return (_resp(f'Saved to <a href="/uploads/{filename}">file</a>', status=200), None)

        def fake_get(url: str, **kwargs):
            if url == state.get("url"):
                return (_resp(state["marker"], status=200), None)
            return (_resp("not found", status=404), None)

        module.requester.post.side_effect = fake_post
        module.requester.get.side_effect = fake_get

        findings = module.run(_endpoint(forms=[self._upload_form()]))
        hits = [f for f in findings if "Stored and Retrievable" in f.title]
        assert len(hits) >= 1
        assert hits[0].severity == Severity.HIGH
        assert hits[0].confidence == Confidence.FIRM
