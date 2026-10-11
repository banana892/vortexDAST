"""Tests for the host-scoped port-scan module and its CLI plumbing."""

from __future__ import annotations

import socket
import threading
import time
from unittest.mock import MagicMock

import pytest

import scanner
from core.crawler import CrawledEndpoint
from scanner import _clamp_subnet_workers, _parse_port_list, _parse_subnet
from scanner import _MAX_SUBNET_WORKERS


def _make_endpoint(url: str, depth: int = 0) -> CrawledEndpoint:
    return CrawledEndpoint(url=url, status_code=200, depth=depth)


def _module():
    cls = scanner.MODULE_REGISTRY["port_scan"]
    return cls(MagicMock())


class _Listener:
    """Minimal TCP listener on an ephemeral port, optionally serving a banner."""

    def __init__(self, banner: bytes | None = None) -> None:
        self._banner = banner
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(5)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop:
            try:
                self._sock.settimeout(0.5)
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                if self._banner:
                    conn.sendall(self._banner)
                time.sleep(0.05)
            except OSError:
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass


# ── Port-list parsing ────────────────────────────────────────────────────────


def test_parse_port_list_none_returns_none():
    assert _parse_port_list(None) is None
    assert _parse_port_list("  ") is None


def test_parse_port_list_singles_and_ranges():
    assert _parse_port_list("22,80,8000-8003") == [22, 80, 8000, 8001, 8002, 8003]


def test_parse_port_list_dedup_and_sort():
    assert _parse_port_list("80,22,80,22") == [22, 80]


def test_parse_port_list_reversed_range():
    assert _parse_port_list("8003-8000") == [8000, 8001, 8002, 8003]


def test_parse_port_list_rejects_out_of_range():
    with pytest.raises(SystemExit):
        _parse_port_list("70000")


def test_parse_port_list_rejects_garbage():
    with pytest.raises(SystemExit):
        _parse_port_list("abc")


# ── Subnet parsing ─────────────────────────────────────────────────────────


def test_parse_subnet_none_returns_none():
    assert _parse_subnet(None, 1024) is None
    assert _parse_subnet("  ", 1024) is None


def test_parse_subnet_single_ip():
    assert _parse_subnet("127.0.0.1", 1024) == ["127.0.0.1"]
    assert _parse_subnet("127.0.0.1/32", 1024) == ["127.0.0.1"]


def test_parse_subnet_small_block_drops_network_broadcast():
    # /30 has 4 addresses; .hosts() yields the 2 usable ones.
    assert _parse_subnet("192.168.1.0/30", 1024) == ["192.168.1.1", "192.168.1.2"]


def test_parse_subnet_slash24_count():
    assert len(_parse_subnet("10.0.0.0/24", 1024)) == 254


def test_parse_subnet_rejects_over_cap():
    with pytest.raises(SystemExit):
        _parse_subnet("10.0.0.0/16", 1024)


def test_parse_subnet_rejects_garbage():
    with pytest.raises(SystemExit):
        _parse_subnet("not-a-cidr", 1024)


# ── Subnet worker clamp ─────────────────────────────────────────────────────


def test_clamp_subnet_workers_within_range():
    assert _clamp_subnet_workers(100) == 100
    assert _clamp_subnet_workers(1) == 1


def test_clamp_subnet_workers_caps_high():
    assert _clamp_subnet_workers(100_000) == _MAX_SUBNET_WORKERS
    assert _MAX_SUBNET_WORKERS == 512


def test_clamp_subnet_workers_floor():
    assert _clamp_subnet_workers(0) == 1
    assert _clamp_subnet_workers(-5) == 1


# ── Subnet sweep behaviour ─────────────────────────────────────────────────


def test_subnet_sweep_scans_all_hosts_once():
    listener = _Listener()
    try:
        mod = _module()
        # Loopback aliases: 127.0.0.1 has the listener, 127.0.0.2 has nothing.
        mod.subnet_hosts = ["127.0.0.1", "127.0.0.2"]
        mod.ports = [listener.port]
        mod.connect_timeout = 0.5
        findings = mod.run(_make_endpoint(f"http://127.0.0.1:{listener.port}/"))
        hosts = {f.extra["host"] for f in findings}
        assert hosts == {"127.0.0.1"}  # only the host with the open port
        # Subnet sweep runs exactly once regardless of further endpoints.
        assert mod.run(_make_endpoint("http://127.0.0.1/other")) == []
    finally:
        listener.close()


def test_subnet_sweep_results_sorted_numerically():
    mod = _module()
    # Exercise the real ordering via a monkeypatched probe over a flat set.
    hosts = ["127.0.0.10", "127.0.0.2"]
    ports = [22, 80]
    open_set = {("127.0.0.2", 22), ("127.0.0.2", 80), ("127.0.0.10", 80)}
    mod._probe_port = lambda h, p: ((h, p) in open_set, "")  # type: ignore[assignment]
    result = mod._scan_many(hosts, ports)
    # 127.0.0.2 sorts before 127.0.0.10 numerically; ports ascending within host.
    assert result == [
        ("127.0.0.2", 22, ""),
        ("127.0.0.2", 80, ""),
        ("127.0.0.10", 80, ""),
    ]


def test_subnet_sweep_parallel_across_hosts():
    # 8 "hosts" that each block for ~0.3s on probe. Sequential would be ~2.4s;
    # a flat pool of 8 workers finishes in well under half that.
    mod = _module()
    hosts = [f"10.0.0.{i}" for i in range(1, 9)]
    ports = [80]
    mod.subnet_workers = 8

    def slow_probe(host, port):
        time.sleep(0.3)
        return False, ""

    mod._probe_port = slow_probe  # type: ignore[assignment]
    start = time.monotonic()
    mod._scan_many(hosts, ports)
    elapsed = time.monotonic() - start
    assert elapsed < 1.0, f"sweep not parallel across hosts (took {elapsed:.2f}s)"


# ── Registry / opt-in behaviour ───────────────────────────────────────────────


def test_port_scan_excluded_from_all():
    assert "port_scan" not in _module_names_in_all()


def _module_names_in_all():
    from scanner import _resolve_modules

    return _resolve_modules("all")


def test_port_scan_registered():
    assert "port_scan" in scanner.MODULE_REGISTRY


# ── Scanning behaviour ─────────────────────────────────────────────────────────


def test_detects_open_port_and_skips_closed():
    listener = _Listener()
    # A very likely-closed port: an ephemeral socket we bind then immediately free.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    try:
        mod = _module()
        mod.ports = [listener.port, closed_port]
        mod.connect_timeout = 1.0
        findings = mod.run(_make_endpoint(f"http://127.0.0.1:{listener.port}/"))
        found_ports = {f.extra["port"] for f in findings}
        assert listener.port in found_ports
        assert closed_port not in found_ports
    finally:
        listener.close()


def test_grabs_banner():
    listener = _Listener(banner=b"SSH-2.0-OpenSSH_9.6 Test\r\n")
    try:
        mod = _module()
        mod.ports = [listener.port]
        mod.connect_timeout = 1.0
        findings = mod.run(_make_endpoint(f"http://127.0.0.1:{listener.port}/"))
        assert findings
        assert "SSH-2.0-OpenSSH_9.6 Test" in findings[0].extra["banner"]
        assert findings[0].confidence.value == "certain"
    finally:
        listener.close()


def test_runs_once_per_host():
    listener = _Listener()
    try:
        mod = _module()
        mod.ports = [listener.port]
        mod.connect_timeout = 1.0
        first = mod.run(_make_endpoint(f"http://127.0.0.1:{listener.port}/a"))
        second = mod.run(_make_endpoint(f"http://127.0.0.1:{listener.port}/b", depth=1))
        assert first  # scanned on first endpoint
        assert second == []  # deduped on subsequent endpoints of the same host
    finally:
        listener.close()


def test_no_host_returns_empty():
    mod = _module()
    assert mod.run(_make_endpoint("file:///etc/passwd")) == []


def test_risky_service_severity_softened_on_private_host():
    # 6379/redis is 'high' risk → MEDIUM, softened to LOW for loopback hosts.
    listener = _Listener()
    try:
        mod = _module()
        # Pretend the open ephemeral port is redis by overriding the catalog entry.
        mod._catalog[listener.port] = {"service": "redis", "risk": "high", "note": "x"}
        mod.ports = [listener.port]
        mod.connect_timeout = 1.0
        finding = mod.run(_make_endpoint(f"http://127.0.0.1:{listener.port}/"))[0]
        assert finding.extra["risk"] == "high"
        assert finding.severity.value == "low"  # softened from medium on 127.x
        assert "Exposed Service" in finding.title
    finally:
        listener.close()
