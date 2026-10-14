# VortexDAST — Implementation Roadmap

**Last updated:** 2026-10-14

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
5. **interactsh** — ✅ *shipped, now covering SSRF + RCE + SQLi + XXE —
   §5 item 4's OAST gap fully closed.* `adapters/interactsh_adapter.py`
   drives `interactsh-client`, asking it to generate one unique correlation
   domain **per (query parameter, payload) combination** on the target
   **plus one more, always, for a dedicated XXE probe** (`-n`), substitutes
   each rendered payload into its one parameter (others untouched), waits
   out a short grace period, then reads back any DNS/HTTP callback
   (`-json -o`) and attributes it to the exact parameter *and*
   vulnerability class that caused it. Five payload specs run per
   parameter: a plain callback URL (blind SSRF), two OS command-injection
   shapes (`; nslookup <domain> #` and `` `nslookup <domain>` ``,
   confirming blind RCE), and two DBMS-specific blind-SQLi OOB payloads
   (MSSQL `xp_dirtree`, Oracle `UTL_INADDR.get_host_address`) — for the one
   seed URL each adapter currently gets. Total probes are capped
   (`_MAX_PROBES`) alongside the existing per-parameter cap, since 5
   payloads/param multiplies request volume. A target with no query
   parameters skips the per-parameter probes entirely (nothing to
   substitute into), but the client still starts — **blind XXE needs no
   query parameter at all**: it's a dedicated `_send_xxe_probe` that POSTs
   a crafted external-entity XML document (`_render_xxe_payload`, bare
   `application/xml`) straight to the target's own URL, confirmed by the
   same DNS/HTTP callback mechanism as everything else here, surfaced with
   a `<xml body>` placeholder in place of a parameter name since there
   isn't one. **Known limit:** only a bare `application/xml` POST is
   tried — not a SOAP envelope, not a multipart/XML part, and the target's
   existing query parameters (if any) aren't re-sent alongside the body;
   left for a follow-up if a real target's XML endpoint needs a different
   shape to parse the body at all.

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
  dynamically).
  **Concurrency — ✅ shipped:** `max_workers` (CLI `--dynamic-workers`,
  default 1 — unchanged single-page behaviour) renders multiple pages at
  once. Playwright's sync API ties a connection's browser/context/page to
  the thread that created them, so this isn't the static crawler's "shared
  pool, any worker takes any URL" model — each worker thread owns its own
  full Playwright connection/browser/page for its whole lifetime, pulling
  `(url, depth)` pairs off one shared queue, reusing `core/crawler.py`'s
  `_CrawlState` unchanged for the lock-protected result/visited/cap
  bookkeeping. A worker whose own browser never launches (or crashes
  outright) drains its share of the queue as failed instead of silently
  stalling the others' shutdown — `work_q.join()` always completes even if
  every worker's launch fails. Verified against a real local server (same
  endpoint set discovered at `max_workers=1` and `4`; four ~1s pages render
  measurably faster concurrently than sequentially; every worker's launch
  forced to fail via a monkeypatched `BrowserType.launch` still returns
  promptly instead of hanging).
  **Authenticated crawling — ✅ shipped:** `crawl()` now accepts `cookies`
  (a `requests` cookie jar), `extra_headers` (bearer token / operator
  `--header`s) and `http_credentials` (HTTP Basic), building an explicit
  Playwright `BrowserContext` (`extra_http_headers`, `add_cookies()`,
  `http_credentials`) instead of the bare default context — so a
  form-login/OAuth2/Basic-auth session now renders authenticated pages
  during `--dynamic` instead of every page rendering logged out.
  `scanner.py` passes these straight from the same authenticated
  `Requester` already used for the static crawl: `requester.session.cookies`,
  any `Authorization` header `requester.session.headers` carries (OAuth2
  bearer or an operator `--header`) plus the raw `--header` flags, and
  `http_auth` as `http_credentials`. Verified against a real headless
  Chromium run (`tests/test_dom_watcher.py`): a fixture page that echoes
  the request's own `Cookie`/`Authorization` headers back into a link
  confirms the browser actually sent them, and a separate HTTP Basic
  challenge-response page confirms `http_credentials`.
  **Dotless-hostname cookie domain — ✅ fixed.** The originally-suspected gap
  ("a cookie scoped to a different host reached via a redirect during login
  would be mis-attributed") turned out not to reproduce — `requests` itself
  extracts cookies per-hop via its own redirect machinery (confirmed for
  `Requester`'s scope-aware manual redirect walk too, since it still routes
  every hop through `Session.send()`), so a host-only cookie's `.domain` is
  already the real issuing host, not the seed URL's, even across a
  cross-host login redirect. Investigating turned up a real, different bug
  instead: Python's `http.cookiejar` (RFC 2965's `eff_request_host()`)
  appends a synthetic `.local` to any **dotless** hostname's host-only
  cookie domain — a cookie from `http://localhost/login` is stored as
  `cookie.domain == "localhost.local"`, which doesn't match the page
  Playwright actually renders, so the browser silently never sent it back.
  `_to_playwright_cookies` now strips that suffix for host-only cookies
  (`domain_specified=False` is the signal that it's cookiejar's synthetic
  value, never a server's own explicit `Domain=`), fixing authenticated
  `--dynamic` crawling against `localhost` and any other bare lab/container
  hostname. Verified both as a fast unit test against a constructed
  `http.cookiejar.Cookie` and end-to-end against a real headless Chromium
  run and a real `requests` round-trip reproducing the exact
  `"localhost.local"` quirk.
- **API testing** — ✅ *all three sub-items shipped.* Until now nothing in the crawl/parse pipeline carried a JSON body, a content-type,
  or a REST path-param concept: `CrawledEndpoint` (`core/crawler.py`) had
  only `forms`/`links`/`query_params`, and `ParsedForm` (`core/parser.py`)
  is HTML-input-shaped. The one piece of prior art, `nosql_check.py`'s
  `_fuzz_json_body`, just re-serializes an HTML form's own fields as JSON —
  it doesn't discover a real API body at all. Scoped as:
  1. ✅ *shipped:* **Discovery — passive capture, dynamic-crawl-only.**
     `DomWatcher` (`core/dom_watcher.py`) registers a Playwright
     `page.on("request", ...)` listener while driving `--dynamic`'s
     headless Chromium, capturing any outgoing `POST`/`PUT`/`PATCH` call
     whose `Content-Type` is `application/json` (method, URL, parsed body,
     headers) — deduped per (method, URL) and capped at
     `DEFAULT_MAX_CAPTURED_JSON` (40), the same volume-control shape as
     `interactsh_adapter.py`'s `_MAX_PROBES`. Each capture becomes its own
     synthetic `CrawledEndpoint` (new `CapturedJsonRequest` in
     `core/crawler.py`, carried on the new `CrawledEndpoint.json_requests`
     field — default empty, every other module unaffected), merged into
     the scan's endpoint list by `scanner.py`'s existing dynamic-crawl
     merge with no changes needed there. `--no-json-fuzz` (CLI) /
     `crawler.json_fuzz: false` (config) opt out; on by default whenever
     `--dynamic` runs. Static-only scans still get **no** JSON coverage in
     v1 — there's no fallback, since a static pass never executes the
     page's own `fetch()`/XHR calls to observe a body in the first place.
     Verified against a real headless-Chromium run (`tests/test_dom_watcher.py`):
     a fixture page's inline `fetch()` POST is captured as a synthetic
     `/api/widgets` endpoint carrying the exact JSON body sent.
  2. ✅ *shipped:* **Fuzzing — generalize the per-param pattern onto JSON
     leaves and REST path segments**, reusing each module's *existing*
     probe sets rather than adding new ones. The new shared
     `core/json_fuzz.py` walks a nested JSON body into
     ``(path, value)`` leaves (`walk_json_leaves`/`render_path`, e.g.
     `items[0].qty`) and rebuilds the body with one leaf substituted at a
     time (`set_leaf`), and separately finds REST-style path segments that
     look like an object reference — numeric or UUID-shaped
     (`looks_like_object_reference`/`find_fuzzable_path_segments`), the
     same spirit as the numeric-ID heuristic `access_control_check.py`
     already uses for query parameters, extended with UUID detection since
     a path segment carries no parameter name to check against a curated
     list. Both are exposed as uniform `FuzzTarget`s
     (`fuzz_targets_for`) so `sqli_check`/`nosql_check`/`xss_check` each
     added one `_fuzz_json_requests(endpoint)` method that iterates
     `endpoint.json_requests` and feeds every target through their
     *existing* analysis methods unchanged (`_analyse_response`,
     `_evaluate_boolean_diff`, `_evaluate_time_delay` for sqli;
     `_analyse_error`, `_evaluate_operator_diff` for nosql;
     `_check_reflection` for xss). `BaseScannerModule.run(endpoint)` keeps
     its single signature — no new module-interface hook.
     Operator-injection and boolean/time-based blind checks only run
     against body leaves (`FuzzTarget.kind == "body"`), since replacing a
     leaf's value with `{"$ne": ...}` or extending it with a true/false SQL
     condition has no equivalent for a URL path segment; error-based
     coverage still runs against both kinds. `DEFAULT_MAX_LEAVES` (15)
     bounds per-request volume, same concern as every other adapter's own
     cap. **Correction from the original scope above:** `nosql_check.py`'s
     pre-existing flat form-to-JSON hack (`_fuzz_json_body`) was left as
     its own thing rather than rebuilt on the leaf-walker — an HTML form's
     fields are flat by construction, so walking them as a tree would add
     a leaf-walk with no actual nesting to gain; the leaf-walker's value is
     specifically for the genuinely-nested bodies Phase 1 captures from
     real page JS, which `_fuzz_json_requests` targets instead.
     `tests/test_json_fuzz.py` covers the primitives directly; each
     module's own test file covers the wiring (nested-leaf error/operator
     detection, path-segment fuzzing, boolean-/time-based blind on a leaf).
  3. ✅ *shipped:* **Spec import (OpenAPI 3.x, Swagger 2.0, Postman
     Collection v2.1)** — the different-input-source producer this was
     scoped to be: `core/spec_import.py`'s `import_openapi_spec`/
     `import_postman_collection` parse a *local* spec file (`--openapi
     PATH` / `--postman PATH`, JSON or YAML for OpenAPI/Swagger) into the
     exact same synthetic `CrawledEndpoint`/`CapturedJsonRequest` output
     Phase 1's live capture produces, merged into the scan the same
     dedupe-by-URL way as the dynamic crawl — **zero changes to Phase 2's
     fuzzing engine** to consume them, confirming the original scoping
     call. Every path is rebased onto the scan's actual `--target`,
     ignoring the spec's own `servers`/`host` (same "stay on the live
     target" rule nmap/subfinder chaining already follows). A path
     template placeholder (OpenAPI `{id}`, Postman `:id`/`{{id}}`) becomes
     a numeric placeholder, which `core/json_fuzz.py`'s existing
     `looks_like_object_reference` already recognises as fuzzable — no
     changes needed there either. OpenAPI/Swagger request bodies are
     *synthesized* from JSON Schema (the spec's own `example`/`default`/
     `enum` when present, else a type-appropriate placeholder, resolving
     local `$ref`s with a depth cap against self-reference) since a spec
     only has schemas, not literal values; Postman's `request.body.raw` is
     almost always a saved literal example already, so it's just
     `json.loads()`. GET-style operations become plain `query_params`
     endpoints, reusing the GET fuzzers that already exist — only
     POST/PUT/PATCH-with-a-body becomes a `CapturedJsonRequest`. Local
     file input only in v1 — no URL-fetch option, no auto-discovery of
     well-known spec paths (`/openapi.json`, …); a missing/malformed file
     degrades to an empty import with a logged error, never failing the
     scan. `tests/test_spec_import.py` covers both formats, nested
     Postman folders, `$ref` resolution (including the self-referential
     case), and every degrade path.
  - **Non-goals:** schema-aware fuzzing (type coercion, enum violations) —
    fuzzing still only substitutes existing injection probes into JSON
    leaves/path segments, it doesn't reason about a schema. `oneOf`/
    `allOf`/`anyOf` schema composition isn't resolved during synthesis —
    upgrade if a real spec needs it.
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
  - ✅ *shipped:* **role matrix** — `--role2-login-data` logs in a second,
    independently authenticated session through the *same* login mechanism
    (`--login-url`/`--login-method`/`--login-success-text`/
    `--login-failure-text`), and `AccessControlCheckModule.set_role_requester()`
    wires it into `access_control_check.py`'s existing sensitive-path and
    object-reference machinery: Part 1's unauthenticated-access check and
    Part 3's new cross-identity check now share one helper
    (`_check_cross_identity_access`), so a second identity reaching a
    sensitive path is reported the same way anonymous access is (`HIGH`/
    `FIRM`) — surfacing vertical privilege escalation. Every object-reference
    parameter the primary session observed is also re-requested *unmodified*
    through the second identity (`_check_role_idor`); unlike Part 2's ±1
    ID-swap guess, a hit here is a genuinely distinct authenticated account
    retrieving the exact same object, so it's reported at `FIRM` rather than
    `TENTATIVE`. **Known limit:** reuses the primary login URL/method/
    success-failure signals rather than taking a fully independent second
    login config — covers the common case (one login form, two accounts);
    an app whose roles log in through genuinely different endpoints needs a
    follow-up.
  - ✅ *shipped:* **OAuth2/OIDC** token flows — `core/auth.py`'s
    `OAuth2Authenticator` exchanges credentials for a bearer access token at
    the authorization server's token endpoint (RFC 6749 §4.3/§4.4) and
    attaches it as `Authorization: Bearer <token>` on the shared session.
    Supports the two grants that complete in a single unattended HTTP call:
    `password` (Resource Owner Password Credentials — a test account's own
    username/password) and `client_credentials` (a service-level client id/
    secret, no end-user account). Shares `FormLoginAuthenticator`'s
    `login`/`is_session_valid`/`reauthenticate` shape, so it plugs into
    `Requester.set_session_recovery` the same way — `is_session_valid`
    returns `False` on a locally-tracked token-lifetime expiry or an
    outright HTTP 401, and `reauthenticate` uses the `refresh_token` grant
    when the authorization server issued one, falling back to the original
    grant otherwise. New CLI flags: `--oauth2-token-url`,
    `--oauth2-grant-type`, `--oauth2-client-id`, `--oauth2-client-secret`,
    `--oauth2-username`, `--oauth2-password`, `--oauth2-scope` — mutually
    exclusive with `--login-url`.
  - ✅ *shipped:* **`authorization_code` + PKCE** (RFC 7636) — the
    interactive grant, which drives a real headless Chromium (Playwright,
    same engine as `DomWatcher`) through the authorization server's own
    login page: navigates to `--oauth2-authorize-url` with a generated PKCE
    challenge, fills `--oauth2-login-data` into the rendered login form's
    inputs by `name` and submits, then reads the authorization code out of
    the server's HTTP redirect `Location` header back to
    `--oauth2-redirect-uri` — via a `page.on("response")` listener, not by
    letting the browser actually navigate there, since Chromium/Playwright
    don't reliably re-route a redirect chained off an already-continued
    request — and exchanges it plus the PKCE verifier for a token.
    `--oauth2-redirect-uri` never needs to resolve to anything real. Shares
    `OAuth2Authenticator`'s `login`/`is_session_valid`/`reauthenticate`
    shape; `reauthenticate` redoes the full browser flow when there's no
    refresh token (a stray subsequent navigation to `redirect_uri`, if the
    browser gets that far, is harmless — the code is already captured by
    then). **Known limit:** only a single login-form submission is driven —
    a login page needing its own MFA step isn't handled — and only an HTTP
    3xx `Location` redirect is recognised, not a client-side (JS/meta-
    refresh) one.
  - ✅ *shipped:* **role matrix for OAuth2** (`--role2-oauth2-*`) — a second,
    independently authenticated `OAuth2Authenticator`, mirroring
    `--role2-login-data`'s "same mechanism, different credentials" shape:
    reuses the primary identity's `--oauth2-token-url`/`--oauth2-grant-type`/
    `--oauth2-scope` (and, for `authorization_code`, `--oauth2-authorize-url`/
    `--oauth2-redirect-uri`), and only the identity-bearing field(s) differ —
    `--role2-oauth2-username`+`--role2-oauth2-password` for `password`,
    `--role2-oauth2-client-id`+`--role2-oauth2-client-secret` for
    `client_credentials`, `--role2-oauth2-login-data` for `authorization_code`
    (`--role2-oauth2-client-id`/`-secret` also double as an override for the
    latter two grants' client registration, if the second identity's differs
    from the primary's). Logs into its own `Requester`, wired into
    `AccessControlCheckModule.set_role_requester()` exactly like the
    form-login role matrix — same `_check_cross_identity_access`/
    `_check_role_idor` machinery, unmodified. Verified end-to-end (two
    distinct `client_credentials` identities against a local IdP, one
    authorized for a resource the other is rejected from) and with a
    role-matrix-specific test (`tests/test_auth.py`) proving two
    simultaneously valid `OAuth2Authenticator` sessions never share state.

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

1. **Authenticated scanning** — ✅ *all follow-ups shipped, including every
   grant's role-matrix equivalent.*
   `core/auth.py` (`FormLoginAuthenticator`) + `Requester.set_session_recovery`
   give form login, CSRF-token harvesting, multi-step/MFA (incl. live TOTP),
   and transparent mid-scan re-auth (replaying every configured step with a
   fresh code). `--role2-login-data` adds a role-matrix second identity for
   form login, and `core/auth.py` (`OAuth2Authenticator`) adds OAuth2/OIDC
   bearer-token auth — `password`/`client_credentials` (single HTTP call)
   and `authorization_code` + PKCE (headless-Chromium-driven) — all three
   with refresh, and all three now with their own role-matrix second
   identity (`--role2-oauth2-*`). See Phase D for detail; nothing is open
   here anymore.
2. **No JS/SPA rendering** — ✅ *resolved by Phase D* (`DomWatcher`,
   `--dynamic`). A thin static-only result is still possible if `--dynamic`
   is left off, but it's no longer the only option.
3. **No API / JSON-body testing** — ✅ *resolved by Phase D.* Captured
   `--dynamic` JSON requests and imported OpenAPI/Swagger/Postman specs
   both feed `sqli_check`/`nosql_check`/`xss_check`'s JSON-leaf and
   REST-path-segment fuzzing (`core/json_fuzz.py`).
4. **No OAST** — ✅ *fully resolved by Phase C.* Blind SSRF/RCE/SQLi
   (MSSQL/Oracle) confirmed via `interactsh`'s GET query-parameter
   substitution; blind XXE confirmed via the same adapter's dedicated,
   parameter-independent probe — a bare `application/xml` POST of a
   crafted external-entity document straight to the target, since this
   class genuinely needed a request body rather than a query-param
   substitution (`_send_xxe_probe`/`_render_xxe_payload`). Runs even
   against a target with no query parameters at all.
5. **Missing vuln classes** — ✅ *native modules shipped for all four.*
   XXE was already covered by Phase B (nuclei templates) plus the dedicated
   blind-XXE OOB probe in Phase C; the remaining four each got their own
   module:
   - `modules/command_injection_check.py` — fuzzes every GET/link/POST
     parameter (no name-gating, unlike SSRF/open-redirect — a shell
     metacharacter can land in any parameter) with five separator styles
     (`;`, `|`, `&&`, backtick, `$()`) chained onto a harmless command.
     Output-based probes (`id`/`ver`) require *every* marker regex to match
     the fuzzed response and *none* to already match the baseline — `HIGH`/
     `FIRM`. Time-based blind probes (`sleep`/`ping`) reuse `sqli_check`'s
     exact threshold-plus-reproduction machinery verbatim. Only read-only,
     non-destructive commands are ever sent.
   - `modules/open_redirect_check.py` — name-gated like SSRF (`url`,
     `next`, `redirect_uri`, …), swaps the value for a benign off-site
     `.invalid` canary (plus one bypass variant built per-endpoint from its
     own host — the userinfo `@` trick) with `allow_redirects=False`. A
     `Location` header whose host is the canary is `CERTAIN`/`MEDIUM`
     (CVSS 6.1 — the textbook open-redirect vector already documented in
     `core/cvss.py`'s own docstring example); a canary URL merely
     pattern-matched inside a meta-refresh/JS redirect in the body (never
     executed) is a weaker `TENTATIVE`/`LOW` fallback.
   - `modules/cors_check.py` — once per distinct origin+path (no param
     fuzzing needed), sends a GET with a random attacker `Origin` and with
     the literal `"null"` origin. `Access-Control-Allow-Origin` reflecting
     either (or `"*"`) is a misconfiguration; paired with
     `Access-Control-Allow-Credentials: true` it's `HIGH`/`CERTAIN` (full
     credentialed cross-origin read); without credentials it's
     `MEDIUM`/`TENTATIVE` (often an intentional public API, left for a
     human to judge).
   - `modules/file_upload_check.py` — every `multipart/form-data` form
     with a file input gets a short, uniquely-marked, inert text upload
     under each of a handful of dangerous extensions (`.php`, `.jsp`,
     `.asp`, `.aspx`, `.svg`, `.html`) with a spoofed `image/jpeg`
     Content-Type. Accepted (no rejection string in the response) is
     `MEDIUM`/`TENTATIVE`; if the response also reveals a path to the
     stored file and re-fetching it returns our own marker text, that's
     upgraded to `HIGH`/`FIRM` — confirmed stored and retrievable.
     Execution is never attempted.
   - **Bugfix found while smoke-testing file_upload_check end-to-end**:
     `core/parser.py`'s `_extract_field` was unconditionally dropping every
     `<input type="file">` — reasonable when nothing looked for one, but it
     meant the crawler never told any module an upload form even existed.
     Fixed to keep it as `field_type="file"` (empty `default_value`, since
     a file input carries no literal value); only `submit`/`button`/
     `reset`/`image` remain excluded.
   - All four are auto-discovered by `scanner.py`'s existing
     `MODULE_REGISTRY` machinery with zero wiring changes, same as every
     other module.
6. **Shallow detectors** — ✅ *all three resolved.*
   - *Time-based blind SQLi:* `sqli_check` runs a dedicated time-based
     heuristic (GET params and POST/form fields) alongside its existing
     error-based and boolean-blind checks: four DBMS-specific delay
     payloads (MySQL `SLEEP()`, PostgreSQL `pg_sleep()`, MSSQL
     `WAITFOR DELAY`, Oracle's privilege-free cartesian-product stall) in
     `payloads/sqli_probes.json`, flagged only when the measured delay
     clears both a relative (60% of the payload's own injected delay) and
     an absolute (2s) threshold *and* reproduces on a second confirmation
     request — so ordinary network/CDN jitter on a slow target can't
     masquerade as an injected delay.
   - *`traversal_check` was GET-only* — ✅ *fixed.* Every POST form now
     gets its own baseline POST (its own fields, unmodified) and each
     field is then fuzzed via POST against that same baseline, through a
     new shared `_probe_param` helper that both the GET and POST paths
     call — same false-positive guards (baseline-pattern skip, HTTP ≥500
     skip, one finding per `(url, param)`) on both paths. GET-param/
     GET-form coverage is unchanged.
   - *`ssrf_check` was keyword-gated* — ✅ *fixed.* It used to only test
     GET/link/form parameters whose *name* matched an SSRF-indicative
     keyword list (`url`, `redirect`, `dest`, …), so a vulnerable parameter
     with an unexpected name (e.g. a generic `q`) was never probed at all.
     The gate (`_is_ssrf_candidate`/`_filter_candidates`/
     `_filter_form_candidates`, plus `url_parameter_keywords` in
     `payloads/ssrf_probes.json`) is removed entirely — every parameter is
     now a candidate, same as `sqli_check`/`command_injection_check`
     already do. The three response signals (status change, timing delta,
     body marker) are what keep this precise, not the parameter's name.

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
- **Edge-WAF-aware backoff** — ✅ *fixed.* `Requester._record_status` now also
  treats a `403` carrying a recognised CDN/WAF fingerprint header (Cloudflare's
  `CF-RAY`/`CF-Mitigated`, Vercel's `X-Vercel-Id`/`X-Vercel-Mitigated`, AWS
  CloudFront's `X-Amz-Cf-Id`, Akamai's `X-Akamai-Transformed`, Sucuri's
  `X-Sucuri-Id`, Imperva/Incapsula's `X-Iinfo`, or a `Server: cloudflare`/
  `sucuri` header) as throttling, since an edge block/challenge page is a
  distinct signal from the application's own 403s and plain 429-halving never
  caught it. It also now parses the actual `Retry-After` value (delta-seconds
  or an HTTP-date, RFC 7231 §7.1.3 — `_parse_retry_after`) and lets an
  explicit value override the blind-doubling ceiling, capped at
  `_MAX_RETRY_AFTER_WAIT` (30s) so one header can't stall a whole scan.
  Everything stays inside the existing non-blocking slot-reservation model —
  no new sleep call, just a larger `_min_interval` the next dispatch already
  honours. **Known limit:** header-fingerprint matching only; a WAF that
  returns a bare 403 with none of these headers (or masks them) still isn't
  detected.

---

## 6. Already shipped (core)

- Concurrent BFS crawler, scope guard, HTML/form/param parser (including
  file-upload `<input>`s).
- 17 auto-discovered scanner modules; thread-safe `Requester` with token-bucket
  rate limiting and 429 auto-throttle.
- Reporting: terminal (themed), JSON, HTML, Markdown, SARIF 2.1.0; CVSS v3.1;
  dedup; suppression rules; severity/confidence filtering; exit codes.
- REST API mode (`core/api.py`) with API-key middleware + job persistence.
- Statistical response-anomaly detection.
- Host-scoped TCP port scan + explicit CIDR subnet sweep (opt-in, capped,
  parallelised).
- Form-login authentication: CSRF-token harvesting, multi-step/MFA (incl.
  live RFC 6238 TOTP), + mid-scan session recovery that replays every step,
  + a role-matrix second identity (`--role2-login-data`) that
  `access_control_check` diffs against the primary session.
- OAuth2/OIDC bearer-token authentication (`password`/`client_credentials`/
  `authorization_code`+PKCE grants + refresh-token recovery), as an
  alternative to form login, with its own role-matrix second identity
  (`--role2-oauth2-*`) for every grant.
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
- 2026-10-13 — Phase D API testing, discovery half shipped: `DomWatcher`
  now passively captures JSON `fetch`/XHR calls a page's own JS makes
  during `--dynamic` crawling (`page.on("request")`, deduped/capped), each
  one becoming a synthetic `CrawledEndpoint` via the new
  `CapturedJsonRequest`/`json_requests` field. `--no-json-fuzz` /
  `crawler.json_fuzz` opt out. The fuzzing half (JSON-leaf and REST
  path-segment substitution) and spec import remain open.
- 2026-10-13 — Phase D API testing, fuzzing half shipped: new shared
  `core/json_fuzz.py` (leaf-walker + REST path-segment detection, exposed
  as uniform `FuzzTarget`s) lets `sqli_check`/`nosql_check`/`xss_check`
  each fuzz captured JSON requests' (possibly nested) bodies and
  object-reference-shaped path segments through their own existing
  analysis methods — no new detection logic, no new module-interface hook.
  Operator-injection and boolean-/time-based blind checks run against body
  leaves only; error-based/reflection checks run against both leaves and
  path segments. `nosql_check.py`'s pre-existing flat form-to-JSON hack
  was deliberately left alone rather than forced onto the leaf-walker — a
  form's fields are flat by construction, so there's no real nesting to
  gain there; the leaf-walker's value is for the genuinely-nested bodies
  Phase 1 captures from real page JS. Only OpenAPI/Swagger/Postman spec
  import remains open for Phase D's "API testing" item.
- 2026-10-13 — Phase D API testing complete: `core/spec_import.py` adds
  `--openapi PATH` (OpenAPI 3.x/Swagger 2.0, JSON or YAML) and `--postman
  PATH` (Postman Collection v2.1) import, producing the same
  `CrawledEndpoint`/`CapturedJsonRequest` shape Phase 1's live capture
  does — merged the same dedupe-by-URL way, no changes to Phase 2's
  fuzzing engine needed. Request bodies are synthesized from JSON Schema
  (`example`/`default`/`enum`, else type-appropriate placeholders, local
  `$ref` resolution with a depth cap); Postman bodies are parsed literally.
  Path templates (`{id}`, `:id`, `{{id}}`) become numeric placeholders,
  already fuzzable via the existing path-segment detection. Local file
  input only — no URL fetch, no well-known-path auto-discovery. All three
  "API testing" sub-items (discovery, fuzzing, spec import) are now
  shipped.
- 2026-10-14 — OAuth2/OIDC authentication shipped, closing the last open
  item under "Authenticated scanning — follow-ups":
  `core/auth.py`'s `OAuth2Authenticator` obtains a bearer access token from
  the authorization server's token endpoint (`password` or
  `client_credentials` grant) and attaches it to the shared session; it
  shares `FormLoginAuthenticator`'s shape so it plugs into
  `Requester.set_session_recovery` the same way, refreshing via the
  `refresh_token` grant on local expiry or an HTTP 401. New flags:
  `--oauth2-token-url`, `--oauth2-grant-type`, `--oauth2-client-id`,
  `--oauth2-client-secret`, `--oauth2-username`, `--oauth2-password`,
  `--oauth2-scope` (mutually exclusive with `--login-url`). The interactive
  `authorization_code` (+ PKCE) grant, which needs a real browser redirect,
  is not implemented.
- 2026-10-14 — Role-matrix second identity shipped: `--role2-login-data`
  authenticates a second session through the same login mechanism, and
  `AccessControlCheckModule.set_role_requester()` wires it into Part 1's
  sensitive-path check (generalized into a shared helper,
  `_check_cross_identity_access`) and a new direct cross-identity
  object-reference check (`_check_role_idor`) — FIRM confidence since it's a
  real second account, not an ID-swap guess. OAuth2/OIDC remains the one
  open item under "Authenticated scanning — follow-ups."
- 2026-10-13 — Blind XXE shipped, closing §5 item 4's OAST gap
  completely: `interactsh_adapter.py` gained a dedicated,
  parameter-independent probe (`_send_xxe_probe`/`_render_xxe_payload`)
  that POSTs a crafted external-entity XML document (bare
  `application/xml`) straight to the target's own URL — unlike the
  existing SSRF/RCE/SQLi probes, it needs no query parameter and so now
  always runs, even against a target with none. Confirmed via the same
  DNS/HTTP OOB callback mechanism as the other three classes; surfaced
  with a `<xml body>` placeholder in place of a parameter name. Known
  limit: only a bare `application/xml` POST is tried, not a SOAP envelope
  or other XML delivery shape.
- 2026-10-14 — §5 item 5 "missing vuln classes" closed: four new native
  modules (`command_injection_check`, `open_redirect_check`, `cors_check`,
  `file_upload_check`), auto-discovered by the existing `MODULE_REGISTRY`
  machinery with no wiring changes. `command_injection_check` reuses
  `sqli_check`'s time-based-blind threshold-plus-reproduction machinery
  verbatim for its blind probes, plus an output-marker check requiring
  every marker regex to match the fuzzed response and none to match the
  baseline. `open_redirect_check` is name-gated like `ssrf_check` and
  confirms via the `Location` header's parsed host (CVSS 6.1, the vector
  already documented in `core/cvss.py`'s own docstring example). `cors_check`
  runs once per origin+path, testing a random attacker `Origin` and the
  literal `"null"` origin. `file_upload_check` uploads a short,
  uniquely-marked, inert text body under dangerous extensions with a
  spoofed image Content-Type, upgrading to confirmed/`FIRM` when the
  response reveals a retrievable stored-file path. While smoke-testing the
  last one end-to-end, found and fixed a real bug it exposed:
  `core/parser.py`'s `_extract_field` was unconditionally dropping every
  `<input type="file">`, so no module could ever have found an upload form
  at all — fixed to keep it as `field_type="file"`.
- 2026-10-14 — Edge-WAF-aware backoff shipped: `Requester._record_status`
  recognises CDN/WAF edge-block fingerprint headers (Cloudflare, Vercel, AWS
  CloudFront, Akamai, Sucuri, Imperva/Incapsula) on a `403` and treats it as
  throttling, reusing the existing halve/floor/ceiling/recovery machinery.
  `Retry-After` is now also parsed for its actual value (delta-seconds or an
  HTTP-date) rather than only gating on presence, and an explicit value
  overrides the blind-doubling ceiling (capped at 30s). Last open item under
  "Operational / safety."
- 2026-10-14 — `DomWatcher` authenticated-crawling shipped, closing its
  "unauthenticated only" shortcut: `crawl()` now accepts `cookies`,
  `extra_headers` and `http_credentials`, which build an explicit Playwright
  `BrowserContext` (`extra_http_headers`, `add_cookies()`, `http_credentials`)
  instead of the bare default one. `scanner.py` wires these from the same
  authenticated `Requester` used for the static crawl, so `--dynamic` now
  renders behind a form-login/OAuth2/Basic-auth session instead of every
  page coming back logged out. Verified against a real headless Chromium
  run: a fixture page that echoes its own request headers back into a link
  proves the browser actually sent the cookie/bearer token, and a separate
  HTTP Basic challenge-response page proves `http_credentials`. `DomWatcher`
  being single-threaded remains the one open shortcut on this module.
- 2026-10-14 — §5 item 6 "shallow detectors" closed, the last open item in
  that section: `traversal_check` gained POST-form coverage (a new shared
  `_probe_param` helper backs both the existing GET path and a new POST
  path, each with its own baseline and the same false-positive guards), and
  `ssrf_check`'s keyword-gating was removed entirely — every GET/link/form
  parameter is now a candidate, not just ones whose name matched an
  SSRF-indicative keyword list. Verified end-to-end against a local server:
  a POST form's `file` field now reports LFI, and a GET parameter named `q`
  (matching no keyword) now reports SSRF.
- 2026-10-15 — OAuth2 `authorization_code` + PKCE grant shipped, closing the
  last open item under "Authenticated scanning": `OAuth2Authenticator` now
  drives a real headless Chromium through the authorization server's login
  page (generates the PKCE challenge, fills `--oauth2-login-data` into the
  rendered form by input `name`, submits) and reads the authorization code
  out of the redirect `Location` header back to `--oauth2-redirect-uri` —
  via a response listener, since Chromium/Playwright don't reliably
  re-route a redirect chained off an already-continued request, so
  `page.route()` interception (the original approach) silently never saw
  it. `--oauth2-redirect-uri` never needs to resolve to anything real.
  New CLI flags: `--oauth2-authorize-url`, `--oauth2-redirect-uri`,
  `--oauth2-login-data`; `--oauth2-grant-type` gained the `authorization_code`
  choice. Verified against a real headless Chromium run and a local
  from-scratch OAuth2/PKCE IdP (`tests/test_auth.py`): full login→code→token
  flow, wrong credentials rejected, a redeemed code can't be replayed, and
  `reauthenticate` without a refresh token redoes the full browser login.
  Known limits: only a single login-form submission is driven (no MFA step
  on the IdP's own login page) and only an HTTP 3xx redirect is recognised,
  not a client-side one; OAuth2 still has no role-matrix equivalent.
- 2026-10-15 — OAuth2 role-matrix second identity shipped (`--role2-oauth2-*`),
  the last open item under "Authenticated scanning": a second
  `OAuth2Authenticator`, same "same mechanism, different credentials" shape
  as `--role2-login-data`, reusing the primary identity's token endpoint/
  grant/scope (and authorize URL/redirect URI for `authorization_code`) and
  overriding only the identity-bearing field(s) — username/password,
  client id/secret, or a second IdP login-form submission, depending on
  grant. Wired into `AccessControlCheckModule.set_role_requester()` exactly
  like the form-login role matrix, with no changes to that module's
  cross-identity/IDOR logic. Verified end-to-end (two distinct
  `client_credentials` identities against a local IdP, one authorized for a
  resource the other is correctly rejected from) and with a dedicated test
  proving two simultaneously valid `OAuth2Authenticator` sessions share no
  state. Closes "Authenticated scanning" completely — no open items remain.
- 2026-10-15 — `DomWatcher` concurrency shipped (`--dynamic-workers`),
  closing its "single-threaded" shortcut: each worker thread owns its own
  full Playwright connection/browser/page for its whole lifetime (sync-API
  resources are tied to the thread that created them, so they can't be
  shared the way the static crawler's pool shares one HTTP session), pulling
  work off one shared queue; `core/crawler.py`'s `_CrawlState` is reused
  unchanged for the lock-protected result/visited/cap bookkeeping. A worker
  whose browser never launches drains its share of the queue as failed
  rather than hanging the others' `work_q.join()`. Default `max_workers=1`
  keeps the original single-page behaviour unchanged; CLI opt-in via
  `--dynamic-workers N`. Verified against a real local server: identical
  endpoint set discovered at `max_workers=1` vs. `4`, a measurable wall-clock
  speedup rendering four ~1s pages concurrently, and every worker's launch
  forced to fail (monkeypatched `BrowserType.launch`) still returns promptly
  instead of hanging.
- 2026-10-15 — `DomWatcher`'s dotless-hostname cookie bug fixed, closing its
  last open cookie-domain shortcut: investigation showed the
  originally-suspected "cross-host redirect mis-attribution" doesn't
  actually occur (`requests` extracts cookies per-hop with the real issuing
  host, including through `Requester`'s scope-aware manual redirect walk),
  but turned up a real bug instead — Python's `http.cookiejar` appends a
  synthetic `.local` to a dotless host's (`localhost`, a bare lab/container
  hostname, ...) host-only cookie domain, which silently never matches the
  page Playwright renders. `_to_playwright_cookies` strips that suffix for
  host-only cookies (`domain_specified=False`), leaving any server's own
  explicit `Domain=` untouched. Verified with a unit test against a
  constructed `http.cookiejar.Cookie` and an end-to-end real-Chromium +
  real-`requests` round-trip reproducing the exact `"localhost.local"`
  quirk.
