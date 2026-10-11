"""
VortexDAST – tests/test_data_chaining.py
────────────────────────────────────────────────────────────────────────────
Full data-chaining (Phase E): nmap's discovered ports and subfinder's
discovered subdomains feed httpx, and httpx's confirmed live services feed
the content/vuln scanners (nuclei, ffuf, nikto, testssl) — instead of every
adapter only ever testing the single seed URL.

Hermetic, like ``test_orchestration_cli.py``: drives the real ``run_scan``
against an in-process HTTP server, with dynamic fake nmap/httpx/nuclei
binaries that echo back whatever target they were actually invoked with —
so the assertions can tell *how many* distinct URLs each adapter was run
against, not just whether it ran at all.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from adapters.httpx_adapter import HttpxAdapter
from core.orchestrator import ScanContext
from scanner import _build_parser, run_scan

# ─────────────────────────────────────────────────────────────────────────────
# Fake binaries — all argv-dynamic, so we can see exactly what each adapter
# was actually invoked with, not just a fixed canned response.
# ─────────────────────────────────────────────────────────────────────────────

# One open, unrelated-looking port (8080) on the target host — nmap XML with
# everything else trimmed to the minimum the adapter's parser needs.
_FAKE_NMAP = r'''#!/usr/bin/env python3
print("""<?xml version="1.0"?>
<nmaprun>
<host><status state="up" reason="user-set"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/><service name="http-proxy" method="table" conf="3"/></port>
</ports>
</host>
</nmaprun>""")
'''

# Handles both call styles: single `-u <target>` (no extra ports to add) and
# the stdin multi-target form the adapter switches to once there are some.
_FAKE_HTTPX = r'''#!/usr/bin/env python3
import sys, json
if "-u" in sys.argv:
    targets = [sys.argv[sys.argv.index("-u") + 1]]
else:
    targets = [line.strip() for line in sys.stdin if line.strip()]
for t in targets:
    print(json.dumps({"url": t, "status_code": 200, "webserver": "fake"}))
'''

# Echoes back whatever -u target it was called with, as its one finding's
# matched-at field — lets a test see exactly which URLs it was run against.
_FAKE_NUCLEI = r'''#!/usr/bin/env python3
import sys, json
target = sys.argv[sys.argv.index("-u") + 1]
print(json.dumps({
    "template-id": "fake-hit",
    "info": {"name": "fake hit", "severity": "critical"},
    "matched-at": target,
}))
'''

# One discovered subdomain unrelated-looking to the seed target, like nmap's
# fake port 8080 above but for ScanContext.discovered_hosts.
_FAKE_SUBFINDER = r'''#!/usr/bin/env python3
import json
print(json.dumps({"host": "sub.example.invalid", "input": "example.invalid", "source": "fake"}))
'''


def _write_fake(dir_path: Path, name: str, source: str) -> Path:
    script = dir_path / name
    script.write_text(source)
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


@pytest.fixture
def chained_tools_on_path(tmp_path, monkeypatch) -> Path:
    _write_fake(tmp_path, "nmap", _FAKE_NMAP)
    _write_fake(tmp_path, "httpx", _FAKE_HTTPX)
    _write_fake(tmp_path, "nuclei", _FAKE_NUCLEI)
    _write_fake(tmp_path, "subfinder", _FAKE_SUBFINDER)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    return tmp_path


@pytest.fixture
def target_site() -> Iterator[str]:
    class Site(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b"<html><body>hello</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()


def _scan(target: str, out: Path, *extra: str) -> Tuple[int, Dict[str, Any]]:
    args = _build_parser().parse_args([
        "-u", target, "-m", "headers_audit", "--max-depth", "0",
        "--rate-limit", "0", "--disable-anomaly-detection",
        "-o", str(out), *extra,
    ])
    code = run_scan(args)
    return code, json.loads(out.read_text())


def _matched_urls(report: Dict[str, Any], tool: str) -> List[str]:
    return [
        f["url"] for f in report["findings"]
        if (f.get("extra") or {}).get("tool") == tool
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Unit: HttpxAdapter._extra_candidate_urls
# ─────────────────────────────────────────────────────────────────────────────


class TestHttpxExtraCandidates:
    def test_no_open_ports_means_no_extras(self):
        assert HttpxAdapter._extra_candidate_urls("http://app.local/", ScanContext()) == []

    def test_adds_http_and_https_for_each_other_port(self):
        ctx = ScanContext()
        ctx.open_ports["app.local"] = [8080, 8443]
        urls = HttpxAdapter._extra_candidate_urls("http://app.local/", ctx)
        assert urls == [
            "http://app.local:8080", "https://app.local:8080",
            "http://app.local:8443", "https://app.local:8443",
        ]

    def test_skips_the_port_already_in_the_target(self):
        ctx = ScanContext()
        ctx.open_ports["app.local"] = [80, 8080]
        urls = HttpxAdapter._extra_candidate_urls("http://app.local:80/", ctx)
        assert urls == ["http://app.local:8080", "https://app.local:8080"]

    def test_caps_extreme_port_counts(self):
        ctx = ScanContext()
        ctx.open_ports["app.local"] = list(range(1000, 1100))
        urls = HttpxAdapter._extra_candidate_urls("http://app.local/", ctx)
        assert len(urls) == 40  # _MAX_EXTRA_PORTS=20 ports × 2 schemes


class TestHttpxExtraSubdomains:
    def test_no_discovered_hosts_means_no_extras(self):
        assert HttpxAdapter._extra_subdomain_urls("http://app.local/", ScanContext()) == []

    def test_adds_http_and_https_for_each_discovered_host(self):
        ctx = ScanContext()
        ctx.discovered_hosts = ["api.app.local", "dev.app.local"]
        urls = HttpxAdapter._extra_subdomain_urls("http://app.local/", ctx)
        assert urls == [
            "http://api.app.local", "https://api.app.local",
            "http://dev.app.local", "https://dev.app.local",
        ]

    def test_skips_the_target_s_own_host(self):
        ctx = ScanContext()
        ctx.discovered_hosts = ["app.local", "dev.app.local"]
        urls = HttpxAdapter._extra_subdomain_urls("http://app.local/", ctx)
        assert urls == ["http://dev.app.local", "https://dev.app.local"]


# ─────────────────────────────────────────────────────────────────────────────
# End to end: nmap's port → httpx's stdin fan-out → nuclei run per live URL
# ─────────────────────────────────────────────────────────────────────────────


class TestFullChain:
    def test_nuclei_runs_against_the_nmap_discovered_port_too(
        self, chained_tools_on_path, target_site, tmp_path
    ):
        code, report = _scan(
            target_site, tmp_path / "r.json",
            "--tools", "nmap,httpx,nuclei",
        )
        assert code == 2  # fake nuclei's hit is "critical" — CI exit convention

        nuclei_urls = _matched_urls(report, "nuclei")
        # The seed target was always included (no regression)...
        assert any(target_site.rstrip("/") in u for u in nuclei_urls)
        # ...and nuclei also ran against the port nmap discovered, which was
        # never anywhere in the seed URL.
        assert any(":8080" in u for u in nuclei_urls)

    def test_execution_order_is_nmap_then_httpx_regardless_of_cli_order(
        self, chained_tools_on_path, target_site, tmp_path
    ):
        # Asking for them in the "wrong" order must not matter: chaining
        # only works if nmap and httpx still run first.
        code, report = _scan(
            target_site, tmp_path / "r.json",
            "--tools", "nuclei,httpx,nmap",
        )
        assert any(":8080" in u for u in _matched_urls(report, "nuclei"))

    def test_without_nmap_nuclei_still_runs_against_just_the_seed(
        self, chained_tools_on_path, target_site, tmp_path
    ):
        """No port-discovery tool selected → unchanged, single-URL behaviour."""
        code, report = _scan(target_site, tmp_path / "r.json", "--tools", "nuclei")
        nuclei_urls = _matched_urls(report, "nuclei")
        assert len(nuclei_urls) == 1
        assert target_site.rstrip("/") in nuclei_urls[0]

    def test_httpx_also_probes_subfinder_discovered_host(
        self, chained_tools_on_path, target_site, tmp_path
    ):
        code, report = _scan(
            target_site, tmp_path / "r.json",
            "--tools", "subfinder,httpx",
        )
        httpx_urls = _matched_urls(report, "httpx")
        assert any("sub.example.invalid" in u for u in httpx_urls)
        assert any(target_site.rstrip("/") in u for u in httpx_urls)

    def test_subfinder_runs_before_httpx_regardless_of_cli_order(
        self, chained_tools_on_path, target_site, tmp_path
    ):
        code, report = _scan(
            target_site, tmp_path / "r.json",
            "--tools", "httpx,subfinder",
        )
        httpx_urls = _matched_urls(report, "httpx")
        assert any("sub.example.invalid" in u for u in httpx_urls)
