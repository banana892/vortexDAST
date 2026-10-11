"""
VortexDAST – tests/test_remaining_work.py
────────────────────────────────────────────────────────────────────────────
Comprehensive test suite verifying all implemented remaining work:
  • Phase 1: Security & Dependency Hygiene (pinned requirements, CI pip-audit, Dependabot)
  • Phase 2: API Auth & Persistent Storage (APIKeyMiddleware, JobStore file persistence)
  • Phase 3: Anomaly Detection Pipeline Integration (_collect_response_features, execute_scan)
  • Phase 4a: SSTI Header vectors & logic-less engine probes
  • Phase 4b: NoSQL Firebase error patterns & JSON-body operator injection
  • Phase 4c: Transport TLS protocol, cipher suite, and certificate inspection
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.api import APIKeyMiddleware, JobStore, create_app
from core.crawler import CrawledEndpoint, CrawlResult
import core.engine as engine
from core.parser import FormField, ParsedForm
from core.requester import Requester
from modules.base import Confidence, Finding, Severity
from modules.nosql_check import NoSQLCheckModule, _NOSQL_PROBES_PATH
from modules.template_injection import TemplateInjectionModule, _SSTI_PROBES_PATH
from modules.transport_check import TLSInfo, TransportCheckModule
from starlette.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: Security & Dependency Hygiene Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase1DependencyHygiene:
    def test_requirements_pinned(self) -> None:
        req_path = Path(__file__).parent.parent / "requirements.txt"
        assert req_path.is_file()
        content = req_path.read_text(encoding="utf-8")
        lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
        # Every package requirement should be strictly pinned with ==
        for line in lines:
            assert "==" in line, f"Requirement not strictly pinned: {line}"

    def test_dependabot_config_valid(self) -> None:
        dependabot_path = Path(__file__).parent.parent / ".github" / "dependabot.yml"
        assert dependabot_path.is_file()
        content = dependabot_path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
        assert data["version"] == 2
        ecosystems = [up["package-ecosystem"] for up in data["updates"]]
        assert "pip" in ecosystems

    def test_ci_workflow_has_pip_audit(self) -> None:
        ci_path = Path(__file__).parent.parent / ".github" / "workflows" / "ci.yml"
        assert ci_path.is_file()
        content = ci_path.read_text(encoding="utf-8")
        assert "pip-audit" in content
        assert "mypy" in content


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: API Auth & Persistent Storage Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase2APIAuthAndPersistence:
    def test_api_key_auth_blocks_unauthorized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VORTEX_API_KEY", "super-secret-key-123")
        app = create_app()
        with TestClient(app) as client:
            resp = client.get("/modules")
            assert resp.status_code == 401
            assert resp.json()["error"] == "unauthorized"

    def test_api_key_health_remains_public(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VORTEX_API_KEY", "super-secret-key-123")
        app = create_app()
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"

    def test_api_key_bearer_auth_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VORTEX_API_KEY", "super-secret-key-123")
        app = create_app()
        with TestClient(app) as client:
            resp = client.get(
                "/modules",
                headers={"Authorization": "Bearer super-secret-key-123"},
            )
            assert resp.status_code == 200
            assert "headers_audit" in resp.json()["modules"]

    def test_api_key_x_api_key_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VORTEX_API_KEY", "super-secret-key-123")
        app = create_app()
        with TestClient(app) as client:
            resp = client.get(
                "/modules",
                headers={"X-API-Key": "super-secret-key-123"},
            )
            assert resp.status_code == 200

    def test_fails_closed_without_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # No key configured and no opt-in → protected endpoints fail closed.
        monkeypatch.delenv("VORTEX_API_KEY", raising=False)
        monkeypatch.delenv("VORTEX_ALLOW_UNAUTHENTICATED", raising=False)
        app = create_app()
        with TestClient(app) as client:
            resp = client.get("/modules")
            assert resp.status_code == 503
            assert resp.json()["error"] == "server_misconfigured"
            # Liveness stays public even when fail-closed.
            assert client.get("/health").status_code == 200

    def test_allow_unauthenticated_opt_in(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("VORTEX_API_KEY", raising=False)
        monkeypatch.delenv("VORTEX_ALLOW_UNAUTHENTICATED", raising=False)
        app = create_app(allow_unauthenticated=True)
        with TestClient(app) as client:
            assert client.get("/modules").status_code == 200

    def test_env_allow_unauthenticated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("VORTEX_API_KEY", raising=False)
        monkeypatch.setenv("VORTEX_ALLOW_UNAUTHENTICATED", "1")
        app = create_app()
        with TestClient(app) as client:
            assert client.get("/modules").status_code == 200

    def test_job_store_persists_and_reloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store1 = JobStore(persist_dir=tmp_dir)
            job = store1.create("https://example.com/target")
            job.status = "completed"
            job.report = {"total": 0, "findings": []}
            store1.update(job)
            store1.add_event(job.id, {"type": "test_event", "info": "step 1"})

            # Check JSON file written to disk
            job_file = Path(tmp_dir) / f"{job.id}.json"
            assert job_file.is_file()

            # Initialize a new store instance from same directory
            store2 = JobStore(persist_dir=tmp_dir)
            loaded = store2.get(job.id)
            assert loaded is not None
            assert loaded.target == "https://example.com/target"
            assert loaded.status == "completed"
            assert len(loaded.events) == 1
            assert loaded.report == {"total": 0, "findings": []}


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: Anomaly Detection Pipeline Integration Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase3AnomalyPipeline:
    def test_collect_response_features(self) -> None:
        req = MagicMock(spec=Requester)
        mock_resp = MagicMock()
        mock_resp.text = "A" * 100
        mock_resp.headers = {"Content-Type": "text/html", "Server": "mock"}
        req.get.return_value = (mock_resp, None)

        urls = ["https://t.com/1", "https://t.com/2"]
        features, valid_urls = engine._collect_response_features(req, urls)
        assert len(features) == 2
        assert valid_urls == urls
        assert features[0]["body_length"] == 100.0
        assert features[0]["header_count"] == 2.0

    def test_anomaly_findings_generated_for_outliers(self) -> None:
        # Create baseline with 8 normal responses and 1 extreme outlier
        urls = [f"https://t.com/{i}" for i in range(9)]
        features = [
            {"body_length": 500.0, "latency_ms": 30.0, "header_count": 8.0}
            for _ in range(8)
        ]
        # Extreme outlier on body length
        features.append({"body_length": 5000000.0, "latency_ms": 30.0, "header_count": 8.0})

        findings = engine._anomaly_findings(features, urls)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.INFORMATIONAL
        assert f.confidence == Confidence.TENTATIVE
        assert f.url == "https://t.com/8"
        assert "body_length" in f.evidence

    def test_execute_scan_anomaly_integration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        endpoints = [
            CrawledEndpoint(url=f"https://t.com/{i}", status_code=200, depth=0)
            for i in range(8)
        ]
        fake_crawler = MagicMock()
        fake_crawler.crawl.return_value = CrawlResult(seed_url="https://t.com", endpoints=endpoints)
        monkeypatch.setattr(engine, "Crawler", lambda **kw: fake_crawler)

        fake_req = MagicMock()
        # 7 identical responses, 1 massive response
        responses = [
            (MagicMock(text="normal", headers={"a": "1"}), None)
            for _ in range(7)
        ]
        responses.append((MagicMock(text="X" * 1000000, headers={"a": "1"}), None))
        fake_req.get.side_effect = responses
        monkeypatch.setattr(engine, "Requester", lambda **kw: fake_req)

        class DummyMod:
            def __init__(self, requester: Any) -> None:
                pass
            def run(self, ep: Any) -> List[Any]:
                return []

        monkeypatch.setattr(engine, "_resolve_module_registry", lambda: {"dummy": DummyMod})

        report = engine.execute_scan("https://t.com", modules=["dummy"], enable_anomaly_detection=True)
        assert report.metadata["anomaly_detection"] is True
        anomaly_findings = [f for f in report.findings if f.title == "Response Anomaly Detected"]
        assert len(anomaly_findings) >= 1

    def test_cli_scanner_anomaly_flag_parsing(self) -> None:
        """Verify that the CLI scanner accepts the --disable-anomaly-detection flag."""
        import scanner as scanner_module  # noqa: PLC0415

        parser = scanner_module._build_parser()

        # Default: anomaly detection enabled
        args = parser.parse_args(["-u", "http://test.com"])
        assert args.disable_anomaly_detection is False

        # With flag: anomaly detection disabled
        args = parser.parse_args(["-u", "http://test.com", "--disable-anomaly-detection"])
        assert args.disable_anomaly_detection is True


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4a: SSTI Header vectors & logic-less engine tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase4aSSTIHeadersAndLogicLess:
    def test_probes_file_contains_logic_less_and_headers(self) -> None:
        mod = TemplateInjectionModule(MagicMock(), payloads_path=_SSTI_PROBES_PATH)
        assert len(mod._probes) >= 4
        assert len(mod._header_probes) >= 3

        # Confirm logic-less engine probes present
        all_engines = set()
        for p in mod._probes:
            all_engines.update(p.get("engines", []))
        assert "Handlebars" in all_engines or "Mustache" in all_engines or "Pebble" in all_engines

    def test_header_injection_detected(self) -> None:
        req = MagicMock(spec=Requester)
        baseline_resp = MagicMock(text="<html>clean baseline</html>", status_code=200)

        def fake_get(url: str, *args: Any, **kwargs: Any) -> Any:
            headers = kwargs.get("headers", {})
            for hval in headers.values():
                if "vtxSSTI" in hval:
                    return MagicMock(text="<html>vtxSSTI1337ENDvtx</html>", status_code=200), None
            return baseline_resp, None

        req.get.side_effect = fake_get
        mod = TemplateInjectionModule(req, payloads_path=_SSTI_PROBES_PATH)
        ep = CrawledEndpoint(url="https://t.com/profile", status_code=200, depth=0)

        findings = mod.run(ep)
        header_findings = [f for f in findings if f.extra.get("method") == "HEADER"]
        assert len(header_findings) >= 1
        assert header_findings[0].severity == Severity.HIGH
        assert "Header:" in header_findings[0].parameter


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4b: NoSQL Firebase & JSON Body Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase4bNoSQLFirebaseAndJSON:
    def test_firebase_error_patterns_loaded(self) -> None:
        mod = NoSQLCheckModule(MagicMock(), payloads_path=_NOSQL_PROBES_PATH)
        db_labels = {p.db for p in mod._compiled_patterns}
        assert "Firebase" in db_labels
        assert len(mod._json_operator_probes) >= 2

    def test_firebase_error_reported(self) -> None:
        req = MagicMock(spec=Requester)

        def fake_get(url: str, *args: Any, **kwargs: Any) -> Any:
            if "%27" in url or "%22" in url:
                return MagicMock(text="FirebaseError: PERMISSION_DENIED: Missing or insufficient permissions", status_code=400), None
            return MagicMock(text="clean listing", status_code=200), None

        req.get.side_effect = fake_get
        mod = NoSQLCheckModule(req, payloads_path=_NOSQL_PROBES_PATH)
        ep = CrawledEndpoint(
            url="https://t.com/api/users",
            status_code=200,
            depth=0,
            query_params={"id": ["123"]},
        )
        findings = mod.run(ep)
        firebase_findings = [f for f in findings if f.extra.get("db") == "Firebase"]
        assert len(firebase_findings) == 1
        assert "Firebase" in firebase_findings[0].title
        assert firebase_findings[0].severity == Severity.HIGH

    def test_json_body_operator_differential(self) -> None:
        req = MagicMock(spec=Requester)

        def fake_post(url: str, data: Any = None, json: Any = None, *args: Any, **kwargs: Any) -> Any:
            if json and isinstance(json, dict):
                user_val = json.get("username")
                if isinstance(user_val, dict) and "$ne" in user_val:
                    return MagicMock(text="RECORD " * 200, status_code=200), None
                if isinstance(user_val, dict) and "$eq" in user_val:
                    return MagicMock(text="no results", status_code=200), None
            return MagicMock(text="baseline single", status_code=200), None

        req.post.side_effect = fake_post
        mod = NoSQLCheckModule(req, payloads_path=_NOSQL_PROBES_PATH)
        form = ParsedForm(
            action_url="https://t.com/api/login",
            method="POST",
            fields=[FormField(name="username", field_type="text", default_value="user1")],
        )
        ep = CrawledEndpoint(url="https://t.com/login", status_code=200, depth=0, forms=[form])
        findings = mod.run(ep)

        json_op_findings = [f for f in findings if f.extra.get("method") == "POST (JSON)"]
        assert len(json_op_findings) == 1
        assert json_op_findings[0].severity == Severity.MEDIUM
        assert json_op_findings[0].confidence == Confidence.TENTATIVE
        assert "Operator Query-Logic Bypass" in json_op_findings[0].title


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4c: TLS Inspection Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPhase4cTLSInspection:
    def test_deprecated_tls_protocol_finding(self) -> None:
        req = MagicMock(spec=Requester)
        req.probe_tls = lambda host, port: TLSInfo(
            protocol="TLSv1.0",
            cipher_name="ECDHE-RSA-AES128-SHA",
            secret_bits=128,
            cert_verified=True,
        )
        mod = TransportCheckModule(req)
        ep = CrawledEndpoint(url="https://target.example.com/", status_code=200, depth=0)
        findings = mod.run(ep)

        dep = [f for f in findings if "Deprecated TLS Protocol" in f.title]
        assert len(dep) == 1
        assert dep[0].severity == Severity.HIGH
        assert "TLSv1.0" in dep[0].evidence

    def test_weak_cipher_suite_finding(self) -> None:
        req = MagicMock(spec=Requester)
        req.probe_tls = lambda host, port: TLSInfo(
            protocol="TLSv1.2",
            cipher_name="RC4-SHA",
            secret_bits=128,
            cert_verified=True,
        )
        mod = TransportCheckModule(req)
        ep = CrawledEndpoint(url="https://target.example.com/", status_code=200, depth=0)
        findings = mod.run(ep)

        weak = [f for f in findings if "Weak TLS Cipher Suite" in f.title]
        assert len(weak) == 1
        assert weak[0].severity == Severity.MEDIUM
        assert "RC4-SHA" in weak[0].evidence

    def test_cert_validation_failure_finding(self) -> None:
        req = MagicMock(spec=Requester)
        req.probe_tls = lambda host, port: TLSInfo(
            protocol="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            secret_bits=256,
            cert_verified=False,
            cert_error="certificate has expired",
        )
        mod = TransportCheckModule(req)
        ep = CrawledEndpoint(url="https://target.example.com/", status_code=200, depth=0)
        findings = mod.run(ep)

        cert_findings = [f for f in findings if "Certificate Validation Failed" in f.title]
        assert len(cert_findings) == 1
        assert cert_findings[0].severity == Severity.MEDIUM
        assert "expired" in cert_findings[0].evidence

    def test_modern_tls_clean_has_no_findings(self) -> None:
        req = MagicMock(spec=Requester)
        req.probe_tls = lambda host, port: TLSInfo(
            protocol="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            secret_bits=256,
            cert_verified=True,
        )
        mod = TransportCheckModule(req)
        ep = CrawledEndpoint(url="https://target.example.com/", status_code=200, depth=0)
        findings = mod.run(ep)

        tls_findings = [
            f for f in findings
            if any(k in f.title for k in ("TLS", "Cipher", "Certificate"))
        ]
        assert tls_findings == []
