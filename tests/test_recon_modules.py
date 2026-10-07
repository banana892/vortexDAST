"""
VortexDAST – tests/test_recon_modules.py
────────────────────────────────────────────────────────────────────────────
Unit and Integration Tests for Reconnaissance Modules:
  • DirFuzzerModule (Wordlist Path & Sensitive File Discovery)
  • ParamFuzzerModule (Hidden Parameter Fuzzing)
  • TechDetectModule (Tech-Stack Fingerprinting)
  • CLI --recon-only & Dynamic Discovery Integration
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

# Allow imports from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crawler import CrawledEndpoint
from core.requester import Requester
from modules.base import Finding, Severity
from modules.dir_fuzzer import DirFuzzerModule, _COMMON_PATHS_PATH
from modules.param_fuzzer import ParamFuzzerModule, _COMMON_PARAMS_PATH
from modules.tech_detect import TechDetectModule, _TECH_SIGNATURES_PATH
from scanner import MODULE_REGISTRY, _build_parser, _resolve_modules


# ─────────────────────────────────────────────────────────────────────────────
# Test Fixtures & Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _mock_requester() -> MagicMock:
    """Create a mock Requester session for offline tests."""
    req = MagicMock(spec=Requester)
    req.dispatch_concurrent.side_effect = lambda tasks, **kwargs: [t() for t in tasks]
    return req


def _mock_response(
    text: str = "<html>OK</html>",
    status_code: int = 200,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> MagicMock:
    """Create a mock requests.Response object."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode("utf-8")
    resp.headers = headers or {}
    resp.cookies = cookies or {}
    return resp


def _make_endpoint(
    url: str = "https://target.com/page",
    status_code: int = 200,
    headers: Optional[Dict[str, str]] = None,
    query_params: Optional[Dict[str, List[str]]] = None,
) -> CrawledEndpoint:
    return CrawledEndpoint(
        url=url,
        status_code=status_code,
        depth=0,
        response_headers=headers or {},
        query_params=query_params or {},
    )


# ─────────────────────────────────────────────────────────────────────────────
# TestDirFuzzerModule
# ─────────────────────────────────────────────────────────────────────────────


class TestDirFuzzerModule:

    def test_module_metadata(self) -> None:
        mod = DirFuzzerModule(_mock_requester())
        assert mod.name == "dir_fuzzer"
        assert "administrative" in mod.description.lower() or "wordlist" in mod.description.lower()

    def test_loads_real_payload_file(self) -> None:
        mod = DirFuzzerModule(_mock_requester(), payloads_path=_COMMON_PATHS_PATH)
        assert len(mod._paths) >= 50
        paths = [p.path for p in mod._paths]
        assert "/.env" in paths
        assert "/robots.txt" in paths
        assert "/admin/" in paths
        assert "/swagger.json" in paths
        assert "/.git/HEAD" in paths

    def test_missing_payload_file_handled_gracefully(self) -> None:
        mod = DirFuzzerModule(_mock_requester(), payloads_path="/nonexistent/paths.json")
        assert mod._paths == []
        ep = _make_endpoint()
        findings = mod.run(ep)
        assert findings == []

    def test_origin_deduplication(self) -> None:
        """Module must probe the origin only once per session."""
        req = _mock_requester()
        req.get.return_value = (_mock_response("Not Found", 404), None)
        mod = DirFuzzerModule(req)

        ep1 = _make_endpoint("https://target.com/page1")
        ep2 = _make_endpoint("https://target.com/page2")

        mod.run(ep1)
        first_call_count = req.get.call_count
        assert first_call_count > 0

        # Second endpoint on the same host should return [] without additional requests
        mod.run(ep2)
        assert req.get.call_count == first_call_count

    def test_skips_standard_404_and_server_errors(self) -> None:
        req = _mock_requester()
        req.get.return_value = (_mock_response("Not Found", 404), None)
        mod = DirFuzzerModule(req)
        findings = mod.run(_make_endpoint("https://target.com/app"))
        assert findings == []

        # Server error 500
        req.get.return_value = (_mock_response("Internal Server Error", 500), None)
        mod_500 = DirFuzzerModule(req)
        findings_500 = mod_500.run(_make_endpoint("https://target2.com/app"))
        assert findings_500 == []

    def test_discovers_sensitive_env_file_high_severity(self) -> None:
        req = _mock_requester()

        def _get_mock(url: str, **kwargs: Any) -> Any:
            if "vortex_404_check" in url:
                return _mock_response("Not Found", 404), None
            if ".env" in url:
                return _mock_response("DB_PASSWORD=secret123\nAPI_KEY=xyz", 200), None
            return _mock_response("Not Found", 404), None

        req.get.side_effect = _get_mock
        mod = DirFuzzerModule(req)
        findings = mod.run(_make_endpoint("https://target.com/"))

        env_findings = [f for f in findings if ".env" in f.parameter]
        assert len(env_findings) >= 1
        assert env_findings[0].severity == Severity.HIGH
        assert env_findings[0].cvss_score == 7.5
        assert "secret123" in env_findings[0].evidence

    def test_soft_404_suppression_on_custom_200_page(self) -> None:
        """When the server returns custom 200 for 404s, candidate pages with same length are suppressed."""
        req = _mock_requester()
        custom_404_body = "<html><body>Custom 404 Page Not Found</body></html>"

        def _get_mock(url: str, **kwargs: Any) -> Any:
            # Server returns HTTP 200 with custom 404 body for all unknown paths
            return _mock_response(custom_404_body, 200), None

        req.get.side_effect = _get_mock
        mod = DirFuzzerModule(req)
        findings = mod.run(_make_endpoint("https://target.com/"))
        # Soft 404s without matching regex should be suppressed
        assert len(findings) == 0

    def test_soft_404_overridden_by_valid_content_regex(self) -> None:
        """When candidate matches a strict content regex (e.g. .git/HEAD), finding is emitted even with custom 200."""
        req = _mock_requester()
        custom_404_body = "<html><body>Generic Content</body></html>"

        def _get_mock(url: str, **kwargs: Any) -> Any:
            if "vortex_404_check" in url:
                return _mock_response(custom_404_body, 200), None
            if ".git/HEAD" in url:
                return _mock_response("ref: refs/heads/master\n", 200), None
            return _mock_response(custom_404_body, 200), None

        req.get.side_effect = _get_mock
        mod = DirFuzzerModule(req)
        findings = mod.run(_make_endpoint("https://target.com/"))

        git_findings = [f for f in findings if ".git/HEAD" in f.parameter]
        assert len(git_findings) == 1
        assert git_findings[0].severity == Severity.HIGH

    def test_discovers_robots_txt_as_informational(self) -> None:
        req = _mock_requester()

        def _get_mock(url: str, **kwargs: Any) -> Any:
            if "robots.txt" in url:
                return _mock_response("User-agent: *\nDisallow: /admin/", 200), None
            return _mock_response("Not Found", 404), None

        req.get.side_effect = _get_mock
        mod = DirFuzzerModule(req)
        findings = mod.run(_make_endpoint("https://target.com/"))

        robots_findings = [f for f in findings if "robots.txt" in f.parameter]
        assert len(robots_findings) == 1
        assert robots_findings[0].severity == Severity.INFORMATIONAL
        assert robots_findings[0].cvss_score == 0.0

    def test_restricted_admin_portal_403_reported(self) -> None:
        req = _mock_requester()

        def _get_mock(url: str, **kwargs: Any) -> Any:
            if url.rstrip("/").endswith("/admin"):
                return _mock_response("Forbidden", 403), None
            return _mock_response("Not Found", 404), None

        req.get.side_effect = _get_mock
        mod = DirFuzzerModule(req)
        findings = mod.run(_make_endpoint("https://target.com/"))

        admin_findings = [f for f in findings if "/admin/" in f.parameter]
        assert len(admin_findings) == 1
        assert admin_findings[0].severity == Severity.LOW


# ─────────────────────────────────────────────────────────────────────────────
# TestParamFuzzerModule
# ─────────────────────────────────────────────────────────────────────────────


class TestParamFuzzerModule:

    def test_module_metadata(self) -> None:
        mod = ParamFuzzerModule(_mock_requester())
        assert mod.name == "param_fuzzer"
        assert "parameter" in mod.description.lower()

    def test_loads_real_payload_file(self) -> None:
        mod = ParamFuzzerModule(_mock_requester(), payloads_path=_COMMON_PARAMS_PATH)
        assert len(mod._params) >= 40
        param_names = [p.name for p in mod._params]
        for expected in ["debug", "test", "admin", "redirect", "url", "file", "path", "id", "cmd"]:
            assert expected in param_names

    def test_missing_payload_file_handled_gracefully(self) -> None:
        mod = ParamFuzzerModule(_mock_requester(), payloads_path="/nonexistent/params.json")
        assert mod._params == []
        findings = mod.run(_make_endpoint())
        assert findings == []

    def test_baseline_error_returns_empty(self) -> None:
        req = _mock_requester()
        req.get.return_value = (None, "Connection refused")
        mod = ParamFuzzerModule(req)
        findings = mod.run(_make_endpoint("https://target.com/search"))
        assert findings == []

    def test_excludes_existing_query_params(self) -> None:
        req = _mock_requester()
        req.get.return_value = (_mock_response("Normal page", 200), None)
        mod = ParamFuzzerModule(req)

        # 'debug' is already present in query params
        ep = _make_endpoint(
            "https://target.com/api?debug=true",
            query_params={"debug": ["true"]},
        )
        mod.run(ep)

        # Verify that ?debug=1 or candidate values were not injected for the existing param
        for call_args in req.get.call_args_list:
            url_called = call_args[0][0]
            if url_called != ep.url:
                assert "debug=1" not in url_called

    def test_status_code_bypass_anomaly_reported(self) -> None:
        """Baseline 403 changing to 200 with ?admin=1 is reported as MEDIUM finding."""
        req = _mock_requester()
        baseline_resp = _mock_response("Access Denied", 403)
        admin_resp = _mock_response("Welcome Administrator Dashboard", 200)

        def _get_mock(url: str, **kwargs: Any) -> Any:
            if "admin=" in url:
                return admin_resp, None
            return baseline_resp, None

        req.get.side_effect = _get_mock
        mod = ParamFuzzerModule(req)
        findings = mod.run(_make_endpoint("https://target.com/restricted", status_code=403))

        admin_findings = [f for f in findings if f.parameter == "admin"]
        assert len(admin_findings) == 1
        assert admin_findings[0].severity == Severity.MEDIUM
        assert admin_findings[0].cvss_score == 5.3
        assert "403" in admin_findings[0].evidence and "200" in admin_findings[0].evidence

    def test_parameter_reflection_anomaly_reported(self) -> None:
        """Injected test value reflected in response is reported as a finding."""
        req = _mock_requester()
        baseline_resp = _mock_response("<html>Hello user</html>", 200)

        def _get_mock(url: str, **kwargs: Any) -> Any:
            if "query=" in url or "q=" in url:
                return _mock_response("<html>Hello user. Query: test</html>", 200), None
            return baseline_resp, None

        req.get.side_effect = _get_mock
        mod = ParamFuzzerModule(req)
        findings = mod.run(_make_endpoint("https://target.com/search"))

        reflected_findings = [f for f in findings if f.parameter in ("query", "q")]
        assert len(reflected_findings) >= 1
        assert reflected_findings[0].severity == Severity.INFORMATIONAL

    def test_debug_trace_anomaly_reported(self) -> None:
        """Response containing stack trace / debug keywords is reported as MEDIUM."""
        req = _mock_requester()
        baseline_resp = _mock_response("Standard error", 200)
        debug_resp = _mock_response(
            "Traceback (most recent call last):\n  File 'app.py', line 12\nZeroDivisionError",
            200,
        )

        def _get_mock(url: str, **kwargs: Any) -> Any:
            if "debug=" in url:
                return debug_resp, None
            return baseline_resp, None

        req.get.side_effect = _get_mock
        mod = ParamFuzzerModule(req)
        findings = mod.run(_make_endpoint("https://target.com/calc"))

        debug_findings = [f for f in findings if f.parameter == "debug"]
        assert len(debug_findings) == 1
        assert debug_findings[0].severity == Severity.MEDIUM
        assert "Traceback" in debug_findings[0].evidence


# ─────────────────────────────────────────────────────────────────────────────
# TestTechDetectModule
# ─────────────────────────────────────────────────────────────────────────────


class TestTechDetectModule:

    def test_module_metadata(self) -> None:
        mod = TechDetectModule(_mock_requester())
        assert mod.name == "tech_detect"
        assert "fingerprints" in mod.description.lower() or "tech" in mod.description.lower()

    def test_loads_real_signatures_file(self) -> None:
        mod = TechDetectModule(_mock_requester(), payloads_path=_TECH_SIGNATURES_PATH)
        assert len(mod._header_sigs) >= 10
        assert len(mod._cookie_sigs) >= 5
        assert len(mod._script_sigs) >= 5
        assert len(mod._dom_sigs) >= 5

    def test_missing_signatures_file_handled_gracefully(self) -> None:
        mod = TechDetectModule(_mock_requester(), payloads_path="/nonexistent/tech.json")
        findings = mod.run(_make_endpoint())
        assert findings == []

    def test_header_fingerprinting_nginx_and_express(self) -> None:
        req = _mock_requester()
        resp = _mock_response(
            "<html>App</html>",
            200,
            headers={"Server": "nginx/1.21.6", "X-Powered-By": "Express"},
        )
        req.get.return_value = (resp, None)

        mod = TechDetectModule(req)
        findings = mod.run(_make_endpoint("https://target.com/"))

        tech_titles = [f.title for f in findings]
        assert any("Nginx 1.21.6" in t for t in tech_titles)
        assert any("Express.js" in t for t in tech_titles)
        for f in findings:
            assert f.severity == Severity.INFORMATIONAL
            assert f.cvss_score == 0.0

    def test_cookie_fingerprinting_django_and_laravel(self) -> None:
        req = _mock_requester()
        resp = _mock_response(
            "<html>App</html>",
            200,
            cookies={"csrftoken": "abc123token", "laravel_session": "xyz456sess"},
        )
        req.get.return_value = (resp, None)

        mod = TechDetectModule(req)
        findings = mod.run(_make_endpoint("https://target.com/"))

        tech_titles = [f.title for f in findings]
        assert any("Django" in t for t in tech_titles)
        assert any("Laravel" in t for t in tech_titles)

    def test_script_tag_fingerprinting_react_and_nextjs(self) -> None:
        req = _mock_requester()
        html = """
        <!DOCTYPE html>
        <html>
          <head>
            <script src="/_next/static/chunks/main.js"></script>
            <script src="/static/js/react.production.min.js"></script>
          </head>
          <body><div id="__next">Hello</div></body>
        </html>
        """
        resp = _mock_response(html, 200)
        req.get.return_value = (resp, None)

        mod = TechDetectModule(req)
        findings = mod.run(_make_endpoint("https://target.com/"))

        tech_titles = [f.title for f in findings]
        assert any("Next.js" in t for t in tech_titles)
        assert any("React" in t for t in tech_titles)

    def test_dom_marker_fingerprinting_angular(self) -> None:
        req = _mock_requester()
        html = """
        <!DOCTYPE html>
        <html>
          <body>
            <app-root ng-version="15.2.0">Loading...</app-root>
          </body>
        </html>
        """
        resp = _mock_response(html, 200)
        req.get.return_value = (resp, None)

        mod = TechDetectModule(req)
        findings = mod.run(_make_endpoint("https://target.com/"))

        tech_titles = [f.title for f in findings]
        assert any("Angular" in t for t in tech_titles)

    def test_origin_deduplication(self) -> None:
        """The same technology should not be emitted multiple times for the same origin."""
        req = _mock_requester()
        resp = _mock_response("<html>App</html>", 200, headers={"Server": "nginx/1.20.0"})
        req.get.return_value = (resp, None)

        mod = TechDetectModule(req)
        findings1 = mod.run(_make_endpoint("https://target.com/page1"))
        assert len(findings1) == 1

        findings2 = mod.run(_make_endpoint("https://target.com/page2"))
        assert len(findings2) == 0


# ─────────────────────────────────────────────────────────────────────────────
# TestReconCLIIntegration
# ─────────────────────────────────────────────────────────────────────────────


class TestReconCLIIntegration:

    def test_recon_modules_present_in_registry(self) -> None:
        assert "dir_fuzzer" in MODULE_REGISTRY
        assert "param_fuzzer" in MODULE_REGISTRY
        assert "tech_detect" in MODULE_REGISTRY

    def test_registry_contains_at_least_nine_modules(self) -> None:
        assert len(MODULE_REGISTRY) >= 9

    def test_resolve_modules_recon_list(self) -> None:
        resolved = _resolve_modules("tech_detect,dir_fuzzer,param_fuzzer")
        assert resolved == ["tech_detect", "dir_fuzzer", "param_fuzzer"]

    def test_recon_only_cli_flag_parsing(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["-u", "https://target.com", "--recon-only"])
        assert args.recon_only is True
