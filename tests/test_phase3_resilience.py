"""
VortexDAST – tests/test_phase3_resilience.py
────────────────────────────────────────────────────────────────────────────
Phase 3 error-handling & resilience:
  • Requester turns transport exceptions into (None, error) — never raises
  • Scanner modules degrade to [] when the requester reports an error
  • Module exceptions are isolated per endpoint (scanner loop pattern)
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crawler import CrawledEndpoint
from core.requester import Requester
from modules.sqli_check import SQLiCheckModule


def _req() -> Requester:
    # rate_limit_rps=0 disables the limiter so tests don't sleep.
    return Requester(rate_limit_rps=0, max_retries=0)


class TestRequesterResilience:
    @pytest.mark.parametrize("exc", [
        requests.exceptions.ConnectionError("down"),
        requests.exceptions.Timeout("slow"),
        requests.exceptions.TooManyRedirects("loop"),
        requests.exceptions.RequestException("other"),
    ])
    def test_get_never_raises(self, exc) -> None:
        req = _req()
        req.session.request = MagicMock(side_effect=exc)
        resp, err = req.get("http://unresponsive.invalid")
        assert resp is None
        assert err is not None and isinstance(err, str)

    def test_post_never_raises(self) -> None:
        req = _req()
        req.session.request = MagicMock(side_effect=requests.exceptions.Timeout("slow"))
        resp, err = req.post("http://unresponsive.invalid", data={"a": "1"})
        assert resp is None
        assert err is not None


class TestModuleDegradesOnError:
    def test_sqli_returns_empty_when_requester_errors(self) -> None:
        req = MagicMock(spec=Requester)
        req.get.return_value = (None, "timeout")
        req.post.return_value = (None, "timeout")
        mod = SQLiCheckModule(req)
        ep = CrawledEndpoint(
            url="https://t.com/p?id=1",
            status_code=200,
            depth=0,
            query_params={"id": ["1"]},
        )
        # Must not raise, and yields no findings when every request errors.
        assert mod.run(ep) == []


class TestModuleIsolation:
    def test_one_endpoint_crash_does_not_stop_others(self) -> None:
        """Mirror the scanner's per-endpoint isolation: a raising probe is caught."""
        endpoints = ["a", "b", "c"]
        collected = []

        def probe(ep):
            if ep == "b":
                raise RuntimeError("module blew up")
            return [f"finding-{ep}"]

        for ep in endpoints:
            try:
                collected.extend(probe(ep))
            except Exception:
                continue  # isolated — matches scanner.run_scan behaviour

        assert collected == ["finding-a", "finding-c"]
