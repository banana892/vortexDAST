# VortexDAST — Implementation Roadmap

**Last updated:** 2026-10-13

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

**Known follow-up, since resolved:** adapters used to each only ever target
the seed URL — see Phase E's "full data-chaining," now shipped.

### Phase C — Tier-2 adapters (depth)
4. **sqlmap** (REST API) — ✅ *shipped.* `adapters/sqlmap_adapter.py` drives
   `sqlmapapi -s` (bound to `127.0.0.1`, random ephemeral port + per-run
   credentials), creates a task, sets `url`/`batch`, starts the scan, polls
   `/scan/<id>/status` under the usual `--tool-timeout` budget (killing the
   engine if the budget elapses), and maps the `TECHNIQUES` content type from
   `/scan/<id>/data` into `Finding`s (place, parameter, DBMS, technique list,
   payload) — turning a "possible SQLi" lead into a confirmed one. The target
   reaches sqlmap only as an HTTP JSON value, never argv/shell, so there's no
   command-injection surface at all here. Requires `sqlmapapi` on `PATH`
   (bundled with sqlmap; a wrapper script is enough — see Contributing).
5. **interactsh** — ✅ *shipped, now covering SSRF + RCE + SQLi.*
   `adapters/interactsh_adapter.py` drives `interactsh-client`, asking it to
   generate one unique correlation domain **per (query parameter, payload)
   combination** on the target (`-n`), substitutes each rendered payload into
   its one parameter (others untouched), waits out a short grace period, then
   reads back any DNS/HTTP callback (`-json -o`) and attributes it to the
   exact parameter *and* vulnerability class that caused it. Five payload
   specs run per parameter: a plain callback URL (blind SSRF), two OS
   command-injection shapes (`; nslookup <domain> #` and `` `nslookup
   <domain>` ``, confirming blind RCE), and two DBMS-specific blind-SQLi OOB
   payloads (MSSQL `xp_dirtree`, Oracle `UTL_INADDR.get_host_address`) —
   closing most of the §5 item 4 OAST gap for the one seed URL each adapter
   currently gets. Total probes are capped (`_MAX_PROBES`) alongside the
   existing per-parameter cap, since 5 payloads/param multiplies request
   volume. A target with no query parameters is skipped without starting the
   client (nothing to probe). **Still open:** blind XXE needs an XML request
   body, not a query-param substitution — a different delivery mechanism
   from everything else this adapter does, left for a follow-up.

### Phase D — Our own web-app depth (unique value, not outsourced)
These are the things no external tool gives us and that define VortexDAST's
own quality:
- **JavaScript/SPA rendering** — ✅ *shipped.* `core/dom_watcher.py`'s
  `DomWatcher` replaces the `--dynamic` stub with a real headless-Chromium
  BFS crawl: renders each page, waits for the network to settle, then hands
  the rendered DOM to the *same* `HTMLParser` the static crawler uses — so
  every downstream module/dedup/report field behaves identically; the only
  difference is where the HTML came from. Wired into `scanner.py` as an
  additive Phase 2 (`--dynamic` or `crawler.dynamic_crawl: true`): it
  re-crawls the seed with JS rendered and merges in only the endpoints the
  static pass could never have seen, leaving everything static already
  found untouched. Verified against a fake SPA whose links/forms exist only
  after an inline `<script>` runs (0 found statically, fully discovered
  dynamically). Sequential (one browser, no concurrency — Playwright's sync
  API isn't thread-safe the way the static crawler's pool needs) and
  unauthenticated (doesn't carry the scan's cookie jar into the browser
  context yet — that's the authenticated-scanning follow-up below, not
  done here).
- **API testing** — 🚧 *scoped, not started.* Today nothing in the crawl/parse
  pipeline carries a JSON body, a content-type, or a REST path-param concept:
  `CrawledEndpoint` (`core/crawler.py`) has only `forms`/`links`/`query_params`,
  and `ParsedForm` (`core/parser.py`) is HTML-input-shaped. The one piece of
  prior art, `nosql_check.py`'s `_fuzz_json_body`, just re-serializes an HTML
  form's own fields as JSON — it doesn't discover a real API body at all.
  Scoped as:
  1. **Discovery — passive capture, dynamic-crawl-only.** `DomWatcher`
     (`core/dom_watcher.py`) already drives headless Chromium under
     `--dynamic`; add `page.on("request")`/`"requestfinished"` capture of
     any outgoing call with `Content-Type: application/json` (method, URL,
     parsed body, headers), deduped and capped like
     `interactsh_adapter.py`'s `_MAX_PROBES`. A new `CapturedJsonRequest`
     feeds a new `CrawledEndpoint.json_requests` field (default empty —
     every other module unaffected). Static-only scans get **no** JSON
     coverage in v1; a `--no-json-fuzz` opt-out exists but there's no
     static-crawl fallback, since a static pass never executes the page's
     own `fetch()`/XHR calls to observe a body in the first place.
  2. **Fuzzing — generalize the per-param pattern onto JSON leaves and REST
     path segments**, reusing each module's *existing* probe sets rather
     than adding new ones. A new shared `core/json_fuzz.py` walks a nested
     JSON body into `(json-pointer-path, value)` leaves and rebuilds the
     body with one leaf substituted at a time — the JSON equivalent of what
     `sqli_check`/`xss_check`/`nosql_check` already do for query params and
     form fields. The IDOR-style "looks like an object reference"
     ID/UUID-segment regex already in `access_control.py` gets extracted
     into a shared helper so the same modules can also flag and fuzz
     path segments (`/users/{id}`) inside a captured request's URL.
     `BaseScannerModule.run(endpoint)` keeps its single signature — no new
     module-interface hook, just one more source each already-fuzzing
     module iterates (`endpoint.json_requests`, alongside `endpoint.forms`
     today). `nosql_check.py`'s flat form-to-JSON hack gets rebuilt on top
     of the same shared leaf-walker so it gains nesting instead of staying
     a one-off.
  3. **Spec import (OpenAPI/Swagger/Postman) — explicitly deferred**, a
     separate follow-up phase: a different input source (a file, not a
     crawl) that would feed the *same* `json_requests` discovery list, so
     it doesn't change the fuzzing engine above, only adds another producer
     for it.
  - **Non-goals for v1:** schema-aware fuzzing (type coercion, enum
    violations) — v1 only substitutes existing injection probes into JSON
    leaves/path segments, it doesn't reason about a schema it doesn't have.
- **Authenticated scanning — follow-ups** on the shipped scaffold (§5.1):
  - ✅ *shipped:* **login-page CSRF-token harvesting** — `core/auth.py`
    GETs the login (and MFA) page first and merges any hidden form fields
    (the usual home for a per-session token) underneath the configured
    ones, via the same `HTMLParser` the crawler uses. On by default,
    silent no-op against a page that doesn't need it
    (`--no-csrf-harvest` to disable).
  - ✅ *shipped:* **multi-step / MFA** — an optional second step
    (`--mfa-url` + `--mfa-data`) submitted after a successful primary
    login. A field value of `{totp:BASE32SECRET}` is replaced with a live
    RFC 6238 code at submission time *and on every re-authentication* —
    verified against the RFC's published SHA-1 test vectors — so a real
    authenticator-app MFA flow can be scanned unattended; a fixed backup
    code works too.
  - 🚧 *not done:* **OAuth2/OIDC** token flows, and a multi-identity
    **role matrix** (scan as two credentials, diff what each can reach to
    surface broken access control) — both are a different shape of work
    from the form-login scaffold above and still need their own design.

### Phase E — Tier-3 adapters + chaining polish
- ~~ffuf~~ ✅ shipped early (curated-catalogue default wordlist, `-ac`
  soft-404 calibration, honours rate limit/threads/auth).
- ✅ **nikto** shipped. `adapters/nikto_adapter.py` — nikto only writes JSON
  to a file (never stdout), so this one overrides `run()` to point it at a
  temp path and read that back; same argv-safety/timeout/fallback shape as
  every other adapter otherwise. nikto's JSON carries **no severity at
  all** (it surfaces candidates for human triage, not confirmed findings —
  its own docs say so), so everything maps to INFORMATIONAL/TENTATIVE
  except a finding whose `references` cites a CVE, bumped to MEDIUM/FIRM.
- ✅ **testssl.sh** shipped. `adapters/testssl_adapter.py` — same
  file-based-output shape as nikto, but testssl.sh carries its **own**
  severity (`OK`/`INFO`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`/`WARN`) since it's
  reporting directly-observed handshake/certificate facts rather than
  signature matches, so severity maps straight across at CERTAIN
  confidence. `OK` (passed) and `WARN` (tool caveat) are dropped; `INFO` is
  also dropped by default — measured against a live test server, including
  every `INFO` row would turn ~15 real findings into ~170 of pure
  configuration metadata (cipher lists, cert serial numbers, …), drowning
  the signal.
- ✅ **subfinder** shipped. `adapters/subfinder_adapter.py` — passive
  subdomain discovery (public sources only, no packets to the target), one
  informational finding per discovered host. Its discoveries feed
  `ScanContext.discovered_hosts`, a new chain input `HttpxAdapter.run()`
  also walks (alongside nmap's `open_ports`) to probe `http://`/`https://`
  each one, over the same stdin multi-target call — so `subfinder,httpx`
  together answer "what subdomains exist, and which are actually live,"
  not just the one seed URL. `_TOOL_EXECUTION_PRIORITY` now runs nmap and
  subfinder (neither depends on the other) before httpx, same ordering
  guarantee as nmap already had.
- ✅ **Full data-chaining** — shipped. `scanner.py`'s tool loop now:
  1. Runs `nmap` and `httpx` **first**, in that order, regardless of what
     order `--tools`/`"all"` happened to list them in (`_TOOL_EXECUTION_PRIORITY`)
     — the whole chain only works if the discovery data exists before the
     tools that consume it run.
  2. Seeds `ctx.open_ports` from nmap's *own* findings as they come back
     (not only from the built-in `port_scan` module, which is all the old
     code checked — that was a real gap: it meant chaining silently never
     fired when nmap was actually installed and ran, only in the fallback
     case).
  3. `HttpxAdapter.run()` is now overridden: when `ctx.open_ports` has
     entries for the target's host, it probes the seed URL *and* every
     other discovered port (`http://`/`https://` each) in one call, piped
     to httpx over **stdin** (httpx's own multi-target idiom) instead of a
     single `-u`. No extra ports → unchanged single-`-u` behaviour.
  4. `nuclei`/`ffuf`/`nikto`/`testssl` (`_PER_URL_TOOLS` — the adapters that
     test a URL's *content*, not a specific query parameter) run once per
     distinct URL in `[seed target, *ctx.http_services]` via a new
     `_run_adapter_per_url` helper — a fresh adapter instance per URL, so no
     adapter's own per-run state (e.g. sqlmap's ephemeral port/credentials)
     leaks between calls. sqlmap/interactsh stay seed-URL-only: a bare
     discovered `host:port` has no query parameters for them to test, so
     chaining them would just be wasted subprocess launches.

  Verified against a real local network, not just unit tests: nmap found
  real open ports on the test machine (8080, 631, …), httpx's stdin fan-out
  confirmed which were actually live HTTP(S), and nikto then ran against
  each of those in turn — all through the real CLI. `tests/test_data_chaining.py`
  covers the same path hermetically (dynamic fake nmap/httpx/nuclei
  binaries that echo back whatever target they were actually invoked
  with, so the assertions can tell *how many* distinct URLs each adapter
  ran against).

---

## 5. Detection gaps carried forward (VAPT readiness)

From assessing a real modern target (SPA + auth + API, on managed hosting).
Ordered by impact; several are now *resolved by the plan above*.

1. **Authenticated scanning** — ✅ *scaffolded, with follow-ups shipped.*
   `core/auth.py` (`FormLoginAuthenticator`) + `Requester.set_session_recovery`
   give form login, CSRF-token harvesting, multi-step/MFA (incl. live TOTP),
   and transparent mid-scan re-auth (replaying every configured step with a
   fresh code). OAuth2/OIDC and a role-matrix comparison remain — see Phase D.
2. **No JS/SPA rendering** — ✅ *resolved by Phase D* (`DomWatcher`,
   `--dynamic`). A thin static-only result is still possible if `--dynamic`
   is left off, but it's no longer the only option.
3. **No API / JSON-body testing** — most modules fuzz only query params and
   HTML form fields. **Phase D.**
4. **No OAST** — blind SSRF/SQLi/RCE/XXE undetectable. **✅ Blind SSRF, SQLi
   (MSSQL/Oracle) and RCE resolved by Phase C** (`interactsh` adapter, GET
   query parameters). Blind XXE still has no OOB confirmation path — it
   needs an XML request body rather than a query-param substitution, a
   different delivery mechanism from this adapter's other four payloads.
5. **Missing vuln classes** — command injection, open redirect, XXE, CORS,
   file-upload. Largely **covered by Phase B** (nuclei templates); native
   modules optional afterwards.
6. **Shallow detectors** — ✅ *time-based blind SQLi resolved.* `sqli_check`
   now runs a dedicated time-based heuristic (GET params and POST/form
   fields) alongside its existing error-based and boolean-blind checks:
   four DBMS-specific delay payloads (MySQL `SLEEP()`, PostgreSQL
   `pg_sleep()`, MSSQL `WAITFOR DELAY`, Oracle's privilege-free
   cartesian-product stall) in `payloads/sqli_probes.json`, flagged only
   when the measured delay clears both a relative (60% of the payload's own
   injected delay) and an absolute (2s) threshold *and* reproduces on a
   second confirmation request — so ordinary network/CDN jitter on a slow
   target can't masquerade as an injected delay. `traversal_check` is still
   GET-only; `ssrf_check` is still keyword-gated.

### Operational / safety (independent of the toolset)

- **Redirect scope escape** — ✅ *fixed.* `Requester.set_scope_guard()` makes
  redirect following scope-aware: the crawler installs the `ScopeGuard` on the
  shared requester before any scan request, and `_dispatch` then walks the
  redirect chain one hop at a time (via `response.next`, reusing requests'
  method/auth/cookie rebuilding), dropping and logging the first hop that
  leaves scope. An off-scope 30x can no longer carry a probe to an unintended
  host. Native behaviour is retained when no guard is set.
- **API auth fails open** — ✅ *fixed.* `core/api.py` now fails closed: with
  no `VORTEX_API_KEY` configured, protected endpoints return HTTP 503.
  Unauthenticated operation is an explicit opt-in (`--allow-unauthenticated` /
  `VORTEX_ALLOW_UNAUTHENTICATED=1`); `/health` stays public throughout.
- **Webhook SSRF** — ✅ *fixed.* `send_webhook` (the choke point for the API
  `callback_url` and the CLI `--webhook`) now resolves the destination host and
  blocks any that maps to a loopback, RFC1918, link-local (incl. the
  169.254.169.254 metadata endpoint), multicast or reserved address, and never
  follows redirects. Internal targets require an explicit opt-in
  (`--allow-private-webhook` / `VORTEX_ALLOW_PRIVATE_WEBHOOK=1`).
- **Known false positives** — ✅ *fixed.* Dropped the broad `"Database Error"`
  pattern from the Firebase NoSQL signatures (it collided with ordinary SQL
  error pages). The IDOR heuristic now runs only when a session is configured
  (no auth boundary = no IDOR) and only swaps params whose name looks like an
  object reference, so public pages and numeric navigation params (`page`,
  `offset`, …) are no longer flagged.
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
- Form-login authentication: CSRF-token harvesting, multi-step/MFA (incl.
  live RFC 6238 TOTP), + mid-scan session recovery that replays every step.
- Tool orchestration (Phases A + B + C + E, complete): `ToolAdapter`
  framework, `--tools` / `--no-tools` / `--tool-timeout` / `--list-tools`, 9
  adapters (nuclei, nmap, httpx, ffuf, sqlmap, interactsh, nikto,
  testssl.sh, subfinder), and full data-chaining across them (nmap's ports
  + subfinder's subdomains → httpx → every live URL templated by the
  content/vuln scanners) — a real recon→exploit pipeline, not 9 adapters
  each testing one URL in isolation.
- Dynamic (Playwright) crawling (`core/dom_watcher.py`, `--dynamic` /
  `crawler.dynamic_crawl`), additive to the static crawl (Phase D).

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
- 2026-10-11 — Phase C sqlmap adapter shipped: REST-API-driven (`sqlmapapi
  -s`), localhost-only with random per-run port/credentials, confirmed
  injections mapped from the `TECHNIQUES` content type.
- 2026-10-11 — Phase C interactsh adapter shipped: one correlation domain per
  query parameter, DNS/HTTP callback attributed back to its parameter,
  confirming blind SSRF the reflection-based `ssrf_check` can't see. Phase C
  complete (sqlmap + interactsh).
- 2026-10-11 — Phase D JS/SPA rendering shipped: `core/dom_watcher.py`'s
  `DomWatcher` (headless Chromium, same `HTMLParser`/`CrawledEndpoint` model
  as the static crawler) replaces the `--dynamic` stub, wired additively
  into `scanner.py` Phase 2. CI now installs Chromium for real (unmocked)
  browser tests.
- 2026-10-12 — Phase D authenticated-scanning follow-ups (partial) shipped:
  `core/auth.py` now harvests hidden fields (CSRF tokens) from the login/MFA
  page by default before submitting, and supports an optional second
  (MFA) step with live RFC 6238 TOTP generation — re-authentication replays
  both steps with a fresh code each time. New CLI flags: `--mfa-url`,
  `--mfa-data`, `--mfa-method`, `--mfa-success-text`, `--mfa-failure-text`,
  `--no-csrf-harvest`. OAuth2/OIDC and the role-matrix comparison are still
  open.
- 2026-10-12 — Phase E nikto + testssl.sh adapters shipped: both override
  `run()` for file-based (not stdout) JSON output, same argv-safety/timeout
  shape as every other adapter. nikto gets no severity from the tool at
  all (heuristic candidates → INFORMATIONAL/TENTATIVE, CVE-cited → MEDIUM/
  FIRM); testssl.sh gets a real one (direct handshake/cert observations →
  CERTAIN, OK/WARN/INFO dropped to avoid ~170 rows of pure metadata
  drowning ~15 real findings — measured against a live test server). 8/8
  adapters now installed and registered.
- 2026-10-12 — Phase E full data-chaining shipped: nmap/httpx forced to run
  first regardless of `--tools` order; `ctx.open_ports` now seeded from
  nmap's own findings (not only the `port_scan` fallback — this was a real
  gap, chaining silently never fired with nmap actually installed);
  `HttpxAdapter.run()` probes every nmap-discovered port via stdin
  multi-target; `nuclei`/`ffuf`/`nikto`/`testssl` now run once per distinct
  URL `httpx` confirms live, via a fresh adapter instance per URL. Verified
  against a real local network (nmap → httpx → nikto chained for real, not
  mocked) plus a hermetic integration suite.
- 2026-10-12 — Phase E subfinder adapter shipped, closing out Phase E:
  `ScanContext.discovered_hosts` is the new chain input (subfinder's finds),
  `HttpxAdapter` probes those hosts alongside nmap's ports, and
  `_TOOL_EXECUTION_PRIORITY` runs nmap/subfinder before httpx. 9/9 adapters
  now installed and registered.
- 2026-10-12 — `interactsh` adapter extended from SSRF-only to also confirm
  blind OS command injection and blind SQL injection (MSSQL `xp_dirtree`,
  Oracle `UTL_INADDR`) via the same per-parameter OOB-callback mechanism —
  closing most of §5 item 4's OAST gap. Blind XXE remains open (needs an XML
  body, not a query-param substitution).
- 2026-10-13 — `sqli_check` time-based blind SQLi shipped, closing §5 item 6's
  first gap: four DBMS-specific delay probes (MySQL, PostgreSQL, MSSQL,
  Oracle) run after the existing error/boolean-blind checks on both GET
  params and POST/form fields, gated by a relative+absolute delay threshold
  and a reproducing confirmation request to rule out network jitter.
  `nosql_check` also gained a `$regex` operator-differential probe pair
  alongside the existing `$ne`/`$eq` pair.
- 2026-10-13 — Phase D API testing scoped (not yet built): passive JSON
  request capture during `--dynamic` crawl (`DomWatcher` network
  interception), a shared JSON-leaf/REST-path-segment fuzzing layer reusing
  each module's existing probes, and OpenAPI/Swagger/Postman import
  deferred to its own follow-up phase as a second feed into the same
  discovery list.
