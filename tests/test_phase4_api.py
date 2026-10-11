"""
VortexDAST – tests/test_phase4_api.py
────────────────────────────────────────────────────────────────────────────
Phase 4 §5.1 REST API tests (Starlette TestClient).

The scan engine is monkeypatched so no real network traffic occurs — these
tests exercise the API's job lifecycle, validation, and endpoints.
"""

from __future__ import annotations

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from starlette.testclient import TestClient

import core.api as api
from core.engine import ScanReport
from modules.base import Confidence, Finding, Severity


@pytest.fixture
def client(monkeypatch):
    def fake_execute_scan(target, **kwargs):
        progress = kwargs.get("progress")
        if progress:
            progress("crawl_done", {"endpoints": 3})
            progress("complete", {"total": 1})
        return ScanReport(
            target=target,
            findings=[Finding(
                title="Test XSS", severity=Severity.HIGH, confidence=Confidence.FIRM,
                url=target, parameter="q",
            )],
            metadata={"total": 1, "by_severity": {"high": 1}},
        )

    monkeypatch.setattr(api, "execute_scan", fake_execute_scan)
    # These tests exercise functionality, not auth: opt into unauthenticated
    # mode explicitly (the API otherwise fails closed with no key configured).
    app = api.create_app(allow_unauthenticated=True)
    with TestClient(app) as c:
        yield c


def _wait_completed(client, job_id, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = client.get(f"/scan/{job_id}")
        if resp.json()["status"] in ("completed", "failed"):
            return resp.json()
        time.sleep(0.02)
    raise AssertionError("scan did not complete in time")


class TestHealthAndModules:
    def test_health(self, client) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert "headers_audit" in body["modules"]

    def test_modules(self, client) -> None:
        resp = client.get("/modules")
        assert resp.status_code == 200
        assert "xss_check" in resp.json()["modules"]


class TestScanLifecycle:
    def test_submit_returns_202_and_id(self, client) -> None:
        resp = client.post("/scan", json={"target": "https://t.com"})
        assert resp.status_code == 202
        body = resp.json()
        # The job may already be running/completed by the time we read the
        # response (the fast fake engine), so just assert it is a valid state.
        assert body["status"] in ("queued", "running", "completed")
        assert len(body["id"]) > 0

    def test_scan_completes_with_findings(self, client) -> None:
        job_id = client.post("/scan", json={"target": "https://t.com"}).json()["id"]
        result = _wait_completed(client, job_id)
        assert result["status"] == "completed"
        assert result["result"]["summary"]["total"] == 1
        assert result["result"]["findings"][0]["title"] == "Test XSS"

    def test_unknown_scan_404(self, client) -> None:
        assert client.get("/scan/doesnotexist").status_code == 404


class TestValidation:
    def test_missing_target_422(self, client) -> None:
        assert client.post("/scan", json={}).status_code == 422

    def test_non_http_target_422(self, client) -> None:
        resp = client.post("/scan", json={"target": "ftp://x.com"})
        assert resp.status_code == 422

    def test_bad_max_depth_422(self, client) -> None:
        resp = client.post("/scan", json={"target": "https://t.com", "max_depth": 99})
        assert resp.status_code == 422

    def test_invalid_json_400(self, client) -> None:
        resp = client.post("/scan", content=b"{not json", headers={"content-type": "application/json"})
        assert resp.status_code == 400


class TestFailureHandling:
    def test_engine_exception_marks_job_failed(self, client, monkeypatch) -> None:
        def boom(target, **kwargs):
            raise RuntimeError("engine exploded")
        monkeypatch.setattr(api, "execute_scan", boom)

        job_id = client.post("/scan", json={"target": "https://t.com"}).json()["id"]
        result = _wait_completed(client, job_id)
        assert result["status"] == "failed"
        assert "engine exploded" in result["error"]


class TestSSE:
    def test_event_stream_emits_progress(self, client) -> None:
        job_id = client.post("/scan", json={"target": "https://t.com"}).json()["id"]
        _wait_completed(client, job_id)
        with client.stream("GET", f"/scan/{job_id}/events") as resp:
            assert resp.status_code == 200
            body = "".join(resp.iter_text())
        assert "data:" in body
        assert "completed" in body
