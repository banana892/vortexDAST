# VortexDAST — Implementation Roadmap

**Last updated:** 2026-10-09

This is the plan of record for VortexDAST. It supersedes the earlier
phase-based improvement roadmap and the old `docs/REMAINING_WORK.md` digest.

---

## 1. Vision & scope

VortexDAST is **a web-application security scanner with an orchestration
layer.** Two halves, one identity:

1. **Its own depth** — a web-app DAST scanner (crawl → fuzz → report) that we
   build and own.
2. **Breadth by orchestration** — it *drives* best-of-breed external tools
   (nmap, nuclei, httpx, sqlmap, …) rather than re-implementing them, and
   unifies their output into one report.

### The decision: orchestrate, don't re-implement

We explicitly choose the **orchestrator model** over building shallow clones of
every specialist:

- **Rejected (Option A):** a single self-contained binary that is a mini-nmap +
  mini-sqlmap + mini-nuclei. Breadth at the cost of always being a weaker copy.
- **Chosen (Option B):** VortexDAST is the *conductor*. It does web-app scanning
  itself, and calls the real tools when they are installed, gluing crawling,
  authentication, data-passing and unified reporting around them.

**Why:** each specialist (nmap, sqlmap, nuclei) took years to get good. Our
unique value is the glue — crawling, auth, scope, data-chaining, and one clean
report — plus genuine depth on web-app testing. Re-building the specialists is
not a good use of effort; wrapping them is.

### Non-goals

- Not re-implementing nmap's packet engine, sqlmap's extraction engine, or
  nuclei's template corpus.
- Not a required-dependency bundle: every external tool is optional with a
  built-in fallback or a clean skip.
- Not a point-and-shoot tool for unauthorised targets — authorisation and scope
  are first-class.

---

## 2. Orchestration architecture

### The `ToolAdapter` contract

External tools are integrated through a single abstraction that mirrors the
existing `BaseScannerModule`/`Finding` design:

```python
class ToolAdapter(ABC):
    name: str
    binary: str                               # e.g. "nuclei"

    def is_available(self) -> bool: ...        # shutil.which(self.binary)
    def build_command(self, target, ctx) -> list[str]: ...   # argv list
    def parse(self, raw_output: str) -> list[Finding]: ...    # JSON → Findings

    def run(self, target, ctx) -> list[Finding]:
        if not self.is_available():
            return self._fallback(target, ctx)  # built-in equivalent, or skip
        proc = subprocess.run(self.build_command(target, ctx),
                              capture_output=True, text=True, timeout=...)
        return self.parse(proc.stdout)
```

### How VortexDAST talks to each tool

- **Default — subprocess + structured output.** Run the tool as a child
  process, tell it to emit JSON, parse it. nmap `-oX`, nuclei `-jsonl`, nikto
  `-Format json`, httpx `-json`.
- **API — for stateful/long-running tools.** sqlmap is driven via its REST API
  (`sqlmapapi`): start it once, POST a task, poll for results.
- Both styles implement the same `ToolAdapter` interface; the orchestrator does
  not care which is which.

### Cross-cutting requirements (must hold for every adapter)

1. **Detection + fallback** — `shutil.which` gates each adapter. Absent tool →
   built-in fallback (e.g. the TCP port scanner for nmap) or a logged skip. A
   scan never *requires* an external tool.
2. **Command-injection safety** — commands are built as **argv lists**, never
   `shell=True` on an interpolated string. A hostile target/param must never be
   able to inject shell commands onto the operator's machine. This is
   non-negotiable for a security tool.
3. **Unified findings** — every adapter maps into the existing `Finding` model
   (title, severity, confidence, CVSS, evidence, remediation), so reporting,
   SARIF, dedup and filtering work unchanged.
4. **Data passing** — a shared scan context lets one tool's output feed the
   next: `nmap → open ports → httpx → live HTTP services → crawl → nuclei →
   sqlmap`.
5. **Timeouts + budgets** — every subprocess has a hard timeout; the sweep/scan
   honours global request/time budgets.

---

## 3. The integrated toolset

All open-source, CLI-invokable with structured output, optional with fallback.

| Phase | Tool | Role | Licence | Interface |
|------|------|------|---------|-----------|
| Network recon | **nmap** | Port/service/version discovery | GPL | XML (`-oX`) |
| HTTP probing | **httpx** | Which host:port serve HTTP; titles, tech, status | MIT | JSONL (`-json`) |
| Subdomain recon | **subfinder** | Passive subdomain discovery | MIT | JSONL |
| Content discovery | **ffuf** | Fast directory/file brute-force | MIT | JSON |
| Web-server audit | **nikto** | Server misconfig + known dangerous files | GPL | JSON |
| Vuln templates | **nuclei** | ~10k community templates (CVEs, exposures) | MIT | JSONL (`-jsonl`) |
| SQLi confirmation | **sqlmap** | Confirm/exploit SQLi leads | GPL | REST API |
| Blind / OOB | **interactsh-client** | Out-of-band callbacks for blind vulns | MIT | JSON |
| TLS depth | **testssl.sh** | Full cipher/protocol/cert analysis | GPL | JSON |

**Licence note:** we *invoke* these as separate programs (subprocess/API), not
by importing their code, so GPL tools (nmap, sqlmap, nikto, testssl) can be
orchestrated without affecting VortexDAST's own MIT licence. Embedding their
source would change that — the subprocess boundary keeps us clear.

**ProjectDiscovery synergy:** nuclei, httpx, subfinder and interactsh share
conventions and JSON output and chain cleanly — a strong reason to centre the
early adapters there.

---

## 4. Phased roadmap

### Phase A — Orchestration foundation — ✅ shipped
- `core/orchestrator.py`: `ToolAdapter` base, adapter registry (auto-discovery,
  like the module registry), shared scan context, argv-safe subprocess runner
  with timeout, `is_available()` detection.
- Finding-mapping helpers + a generic JSONL parser.
- CLI: `--tools nuclei,nmap,...` / `--tools all` / `--no-tools`;
  `--list-tools` showing which are installed; `--tool-timeout` hard cap.
  Tools run as **Phase 3** of `run_scan`, after the built-in modules; their
  findings share the report, dedup, filters and CI exit code.
- Tests with fake tool binaries (fixture scripts emitting canned JSON) so
  adapter logic is tested without the real tool installed, plus end-to-end
  `run_scan` tests against a local HTTP server.

### Phase B — Tier-1 adapters (highest value, cleanest JSON) — ✅ shipped
1. **nuclei** — biggest leverage; thousands of checks for little code.
2. **nmap** — makes the recon half real (built-in port scanner becomes
   fallback). Parses `-oX` XML; risky services (DBs, remote access, …) are
   MEDIUM, others informational.
3. **httpx** — the glue connecting nmap's open ports to the web scan. Live
   base URLs are chained forward via `ScanContext.http_services`.

**Known follow-ups:** adapters currently each target the seed URL. The
data-chaining plumbing exists (`ScanContext.open_ports` is seeded from
`port_scan`, `http_services` from httpx) but no adapter *consumes* it yet —
e.g. httpx probing every nmap-discovered port, nuclei templating every live
httpx URL. That consumption is the Phase E "full data-chaining" item.

### Phase C — Tier-2 adapters (depth)
4. **sqlmap** (REST API) — turns "possible SQLi" leads into confirmed findings.
5. **interactsh** — OAST listener; unlocks the blind-vuln classes (§5.4).

### Phase D — Our own web-app depth (unique value, not outsourced)
These are the things no external tool gives us and that define VortexDAST's
own quality:
- **JavaScript/SPA rendering** — replace the `--dynamic` stub with a real
  Playwright/CDP crawl worker (`core/dom_watcher.py`). Unblocks modern apps.
- **API testing** — OpenAPI/Swagger/Postman import + REST path-parameter and
  JSON-body fuzzing across modules.
- **Authenticated scanning — follow-ups** on the shipped scaffold (§5.1):
  OAuth2/OIDC, login-page CSRF-token harvesting, multi-step/MFA, role matrix.

### Phase E — Tier-3 adapters + chaining polish
- ~~ffuf~~ ✅ shipped early (curated-catalogue default wordlist, `-ac`
  soft-404 calibration, honours rate limit/threads/auth); nikto, subfinder,
  testssl.sh adapters remain.
- Full data-chaining across the pipeline and a combined recon→exploit report
  view.

---

## 5. Detection gaps carried forward (VAPT readiness)

From assessing a real modern target (SPA + auth + API, on managed hosting).
Ordered by impact; several are now *resolved by the plan above*.

1. **Authenticated scanning** — ✅ *scaffolded.* `core/auth.py`
   (`FormLoginAuthenticator`) + `Requester.set_session_recovery` give form
   login and transparent mid-scan re-auth. Follow-ups in Phase D.
2. **No JS/SPA rendering** — `--dynamic` is a stub. **Phase D.** Until then,
   thin results on a client-rendered app are *not* evidence of a clean app.
3. **No API / JSON-body testing** — most modules fuzz only query params and
   HTML form fields. **Phase D.**
4. **No OAST** — blind SSRF/SQLi/RCE/XXE undetectable. **Resolved by Phase C**
   (interactsh).
5. **Missing vuln classes** — command injection, open redirect, XXE, CORS,
   file-upload. Largely **covered by Phase B** (nuclei templates); native
   modules optional afterwards.
6. **Shallow detectors** — `sqli_check` has no time-based blind (→ Phase C
   sqlmap); `traversal_check` is GET-only; `ssrf_check` is keyword-gated.

### Operational / safety (independent of the toolset)

- **Redirect scope escape** — `Requester` follows redirects via the `requests`
  default and never consults `ScopeGuard`; an off-scope 301/302 can carry
  probes to an unintended host. **Fix before any external engagement** (and
  before orchestration amplifies it).
- **API auth fails open** — `core/api.py` allows all requests when
  `VORTEX_API_KEY` is unset. Should fail closed or require an explicit
  `--allow-unauthenticated`.
- **Webhook SSRF** — `callback_url` validates scheme only; resolve-and-block
  RFC1918/link-local before posting.
- **Known false positives** — Firebase NoSQL pattern includes the broad string
  `"Database Error"` (collides with SQL errors); IDOR heuristic flags public
  GET params.
- **Edge-WAF-aware backoff** — beyond basic 429-halving, detect CDN/WAF
  throttling (e.g. Vercel/Cloudflare) and slow/pause gracefully.

---

## 6. Already shipped (core)

- Concurrent BFS crawler, scope guard, HTML/form/param parser.
- 13 auto-discovered scanner modules; thread-safe `Requester` with token-bucket
  rate limiting and 429 auto-throttle.
- Reporting: terminal (themed), JSON, HTML, Markdown, SARIF 2.1.0; CVSS v3.1;
  dedup; suppression rules; severity/confidence filtering; exit codes.
- REST API mode (`core/api.py`) with API-key middleware + job persistence.
- Statistical response-anomaly detection.
- Host-scoped TCP port scan + explicit CIDR subnet sweep (opt-in, capped,
  parallelised).
- Form-login authentication scaffold + mid-scan session recovery.
- Tool orchestration (Phases A + B): `ToolAdapter` framework, `--tools` /
  `--no-tools` / `--tool-timeout` / `--list-tools`, and nuclei, nmap (with
  built-in port-scan fallback), httpx and ffuf adapters.

---

## 7. Contributing

1. Branch: `feat/<thing>` (adapters: `feat/adapter-<tool>`).
2. Tests first — adapters test against fixture scripts emitting canned JSON, so
   CI needs no external tools installed.
3. Update `README.md` + this file for anything user-visible.
4. Local gate: `pytest tests/ -q && mypy modules/ core/ && ruff check .`
5. PR with a clear description + before/after metrics.

**Document history:**
- 2026-10-07 — Initial phase-based roadmap.
- 2026-10-09 — Rewritten as the orchestrator (Option B) implementation plan;
  added VAPT-readiness gaps; shipped host-scoped port/subnet scanning and the
  authenticated-scanning scaffold.
- 2026-10-09 — Phases A + B shipped: orchestration wired into the CLI
  (`--tools`, `--no-tools`, `--tool-timeout`, `--list-tools`); nuclei, nmap and
  httpx adapters; ffuf adapter pulled forward from Phase E; `adapters/` now
  packaged and type-checked. Next: Phase C (sqlmap REST API, interactsh OAST).
