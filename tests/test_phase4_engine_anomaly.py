"""
VortexDAST – tests/test_phase4_engine_anomaly.py
────────────────────────────────────────────────────────────────────────────
Phase 4 tests:
  • core.engine.execute_scan — programmatic scan engine (mocked crawl/modules)
  • core.anomaly — statistical response anomaly detection
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import core.engine as engine
from core.anomaly import (
    AnomalyDetector,
    ResponseAnomalyDetector,
)
from core.crawler import CrawledEndpoint, CrawlResult
from modules.base import Confidence, Finding, Severity


# ─────────────────────────────────────────────────────────────────────────────
# engine.execute_scan
# ─────────────────────────────────────────────────────────────────────────────


class TestEngine:
    def test_available_modules(self) -> None:
        mods = engine.available_modules()
        assert "xss_check" in mods and "sqli_check" in mods

    def test_unknown_module_raises(self) -> None:
        with pytest.raises(ValueError):
            engine.execute_scan("https://t.com", modules=["nope_check"])

    def test_execute_scan_collects_findings(self, monkeypatch) -> None:
        # Stub the crawler to return two endpoints without any network.
        ep = CrawledEndpoint(url="https://t.com/p", status_code=200, depth=0)
        fake_crawler = MagicMock()
        fake_crawler.crawl.return_value = CrawlResult(seed_url="https://t.com", endpoints=[ep, ep])
        monkeypatch.setattr(engine, "Crawler", lambda **kw: fake_crawler)
        monkeypatch.setattr(engine, "Requester", lambda **kw: MagicMock())

        # Stub the registry with a module that returns one finding per endpoint.
        class FakeModule:
            def __init__(self, requester):
                pass
            def run(self, endpoint):
                return [Finding(title="X", severity=Severity.LOW,
                                confidence=Confidence.FIRM, url=endpoint.url)]

        monkeypatch.setattr(engine, "_resolve_module_registry", lambda: {"fake": FakeModule})

        events = []
        report = engine.execute_scan(
            "https://t.com", modules=["fake"], progress=lambda p, d: events.append(p)
        )
        assert report.metadata["endpoints_scanned"] == 2
        assert report.metadata["total"] >= 1  # deduped across identical endpoints
        assert "complete" in events

    def test_module_exception_isolated(self, monkeypatch) -> None:
        ep = CrawledEndpoint(url="https://t.com/p", status_code=200, depth=0)
        fake_crawler = MagicMock()
        fake_crawler.crawl.return_value = CrawlResult(seed_url="https://t.com", endpoints=[ep])
        monkeypatch.setattr(engine, "Crawler", lambda **kw: fake_crawler)
        monkeypatch.setattr(engine, "Requester", lambda **kw: MagicMock())

        class Boom:
            def __init__(self, requester):
                pass
            def run(self, endpoint):
                raise RuntimeError("module crash")

        monkeypatch.setattr(engine, "_resolve_module_registry", lambda: {"boom": Boom})
        report = engine.execute_scan("https://t.com", modules=["boom"])
        assert report.metadata["total"] == 0  # crash isolated, scan still returns


# ─────────────────────────────────────────────────────────────────────────────
# anomaly detection
# ─────────────────────────────────────────────────────────────────────────────


class TestAnomalyDetector:
    def test_not_ready_below_min_samples(self) -> None:
        d = AnomalyDetector().fit([1, 2, 3])
        assert not d.ready
        assert d.score(1000) == 0.0  # no judgement without enough data

    def test_detects_clear_outlier(self) -> None:
        d = AnomalyDetector().fit([100, 101, 99, 100, 102, 98, 101])
        assert d.ready
        assert d.is_outlier(100000)
        assert not d.is_outlier(100)

    def test_identical_samples_no_false_positive(self) -> None:
        d = AnomalyDetector().fit([50] * 10)
        assert d.score(50) == 0.0
        assert not d.is_outlier(50)

    def test_mild_variation_not_flagged(self) -> None:
        d = AnomalyDetector().fit([100, 102, 98, 101, 99, 100, 103, 97])
        assert not d.is_outlier(104)


class TestResponseAnomalyDetector:
    def test_flags_oversized_response(self) -> None:
        normal = [{"body_length": 500, "latency_ms": 50, "header_count": 10} for _ in range(10)]
        anomalous = {"body_length": 900000, "latency_ms": 50, "header_count": 10}
        det = ResponseAnomalyDetector().fit(normal)
        reasons = det.check(anomalous)
        assert "body_length" in reasons

    def test_clean_response_no_reasons(self) -> None:
        normal = [{"body_length": 500, "latency_ms": 50, "header_count": 10} for _ in range(10)]
        det = ResponseAnomalyDetector().fit(normal)
        assert det.check({"body_length": 505, "latency_ms": 52, "header_count": 10}) == {}

    def test_detect_one_shot_pass(self) -> None:
        obs = [{"body_length": 500, "latency_ms": 40, "header_count": 9} for _ in range(12)]
        obs.append({"body_length": 500, "latency_ms": 40, "header_count": 95})  # outlier header count
        results = ResponseAnomalyDetector().detect(obs)
        assert len(results) == 1
        assert results[0].index == len(obs) - 1
        assert "header_count" in results[0].reasons
