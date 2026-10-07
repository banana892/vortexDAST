"""
VortexDAST – tests/test_phase2_transport.py
Passive transport-security checks: cleartext HTTP, password forms, mixed content, HTTPS redirect.
"""

from __future__ import annotations

import os
import sys
import threading
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.reporter import Reporter
from modules.base import Confidence, Severity
from modules.transport_check import TransportCheckModule
from scanner import MODULE_REGISTRY
from tests.test_recon_modules import _make_endpoint, _mock_requester, _mock_response


def _module(pages: Dict[str, Any], http_redirect: Optional[Any] = "https") -> TransportCheckModule:
    """pages: url -> html. http_redirect: 'https', a (status, location) tuple, or None (port 80 closed)."""
    req = _mock_requester()

    def _get(url: str, allow_redirects: bool = True, **kw: Any) -> Any:
        if allow_redirects is False:
            if http_redirect is None:
                return None, "Connection refused"
            if http_redirect == "https":
                return _mock_response("", 301, headers={"Location": url.replace("http://", "https://", 1)}), None
            status, location = http_redirect
            return _mock_response("<html>plain</html>", status, headers={"Location": location} if location else {}), None
        return _mock_response(pages.get(url, "<html></html>"), 200, headers={"Content-Type": "text/html"}), None

    req.get.side_effect = _get
    return TransportCheckModule(req)


def _titles(findings: list) -> list:
    return sorted(f.title for f in findings)


def test_registered() -> None:
    assert MODULE_REGISTRY["transport_check"] is TransportCheckModule


def test_clean_https_page_has_no_findings() -> None:
    html = '<html><script src="/app.js"></script><img src="https://cdn.x/a.png"><form action="/login"><input type="password"></form></html>'
    mod = _module({"https://t.com/": html})
    assert mod.run(_make_endpoint("https://t.com/")) == []


def test_http_site_reported_once_per_origin() -> None:
    mod = _module({})
    findings = mod.run(_make_endpoint("http://t.com/")) + mod.run(_make_endpoint("http://t.com/about"))
    assert _titles(findings) == ["Site Served Over Unencrypted HTTP"]
    assert findings[0].confidence == Confidence.CERTAIN


def test_password_form_on_http_page_is_high() -> None:
    mod = _module({"http://t.com/login": '<form action="/session"><input type="PASSWORD" name="pw"></form>'})
    pw = [f for f in mod.run(_make_endpoint("http://t.com/login")) if "Password" in f.title]
    assert len(pw) == 1
    assert pw[0].severity == Severity.HIGH
    assert pw[0].parameter == "form[action=http://t.com/session]"


def test_https_page_posting_password_to_http_is_high() -> None:
    mod = _module({"https://t.com/": '<form action="http://t.com/login"><input type="password"></form>'})
    findings = mod.run(_make_endpoint("https://t.com/"))
    assert "Password Form Transmitted Over Unencrypted HTTP" in _titles(findings)
    assert "Active Mixed Content on HTTPS Page" in _titles(findings)


def test_active_and_passive_mixed_content_split_by_severity() -> None:
    html = (
        '<script src="http://cdn.x/a.js"></script>'
        '<link rel="stylesheet" href="http://cdn.x/a.css">'
        '<link rel="icon" href="http://cdn.x/favicon.ico">'
        '<img src="http://cdn.x/a.png"><img src="//cdn.x/ok.png">'
    )
    findings = {f.title: f for f in _module({"https://t.com/": html}).run(_make_endpoint("https://t.com/"))}
    active = findings["Active Mixed Content on HTTPS Page"]
    passive = findings["Passive Mixed Content on HTTPS Page"]
    assert active.severity == Severity.MEDIUM and passive.severity == Severity.LOW
    assert active.extra["insecure_resources"] == ["http://cdn.x/a.js", "http://cdn.x/a.css"]
    assert passive.extra["insecure_resources"] == ["http://cdn.x/a.png"]


def test_http_counterpart_serving_content_is_flagged() -> None:
    findings = _module({}, http_redirect=(200, None)).run(_make_endpoint("https://t.com/"))
    assert _titles(findings) == ["HTTP Endpoint Does Not Redirect to HTTPS"]
    assert "responds with HTTP 200" in findings[0].evidence


def test_http_redirect_to_http_is_flagged() -> None:
    findings = _module({}, http_redirect=(302, "http://www.t.com/")).run(_make_endpoint("https://t.com/"))
    assert _titles(findings) == ["HTTP Endpoint Does Not Redirect to HTTPS"]


def test_closed_port_80_is_not_flagged() -> None:
    assert _module({}, http_redirect=None).run(_make_endpoint("https://t.com/")) == []


def test_custom_https_port_skips_redirect_probe() -> None:
    mod = _module({}, http_redirect=(200, None))
    assert mod.run(_make_endpoint("https://t.com:8443/")) == []
    probed = [c.args[0] for c in mod.requester.get.call_args_list]
    assert all(not u.startswith("http://") for u in probed)


def test_ipv6_host_keeps_brackets() -> None:
    mod = _module({}, http_redirect=(200, None))
    mod.run(_make_endpoint("https://[2001:db8::1]/"))
    assert "http://[2001:db8::1]/" in [c.args[0] for c in mod.requester.get.call_args_list]


def test_non_html_response_skips_page_checks() -> None:
    req = _mock_requester()
    req.get.return_value = (_mock_response('<script src="http://x/a.js"></script>', 200,
                                           headers={"Content-Type": "application/json"}), None)
    assert TransportCheckModule(req).run(_make_endpoint("http://t.com/api")) != []  # origin finding only
    assert all("Mixed" not in f.title for f in TransportCheckModule(req).run(_make_endpoint("https://t.com/api")))


def test_password_form_on_many_pages_groups_to_one_finding() -> None:
    page = '<form action="/login"><input type="password"></form>'
    mod = _module({f"http://t.com/{p}": page for p in ("", "a", "b")})
    raw = []
    for p in ("", "a", "b"):
        raw += mod.run(_make_endpoint(f"http://t.com/{p}"))
    pw = [f for f in Reporter.deduplicate_findings(raw) if "Password" in f.title]
    assert len(pw) == 1 and len(pw[0].extra["affected_urls"]) == 3


def test_concurrent_runs_probe_origin_once() -> None:
    mod = _module({}, http_redirect=(200, None))
    barrier = threading.Barrier(8)
    results: list = []

    def _run() -> None:
        barrier.wait()
        results.extend(mod.run(_make_endpoint("https://t.com/")))

    threads = [threading.Thread(target=_run) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert _titles(results) == ["HTTP Endpoint Does Not Redirect to HTTPS"]
