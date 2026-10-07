# VortexDAST — Improvement Roadmap

**Last Updated:** 2026-10-07

---

## 1. Executive Summary

VortexDAST is a lightweight, modular DAST framework with solid architecture and core functionality. This document outlines prioritized improvements to increase vulnerability detection accuracy, performance, and usability across different threat models and deployment scenarios.

**Key Focus Areas:**
- ✅ Complete partially-implemented reconnaissance modules
- 🎯 Improve finding accuracy (deduplication, confidence scoring)
- 📊 Expand vulnerability coverage (new detector modules)
- ⚡ Optimize scan performance (batching, caching, parallelization)
- 📋 Enhance reporting and integration capabilities

---

## 2. High-Impact Improvements (Phase 1 — Next Sprint)

### 2.1 Complete Reconnaissance Modules

**Status:** ✅ Done (2026-10-07). Correction: the modules were already functional with 30 tests when this roadmap was written. The remaining work was hardening:
- Thread-safe origin/param/tech dedup in all three modules (previously a race under the 10-thread fuzz pool)
- `dir_fuzzer` soft-404 detection now handles catch-all 401/403/redirect responses, not just custom 200 pages
- `dir_fuzzer` probes the wordlist concurrently via `Requester.dispatch_concurrent`
- `param_fuzzer` takes a second baseline to measure natural page jitter before reporting length deltas

**Files:** `modules/dir_fuzzer.py`, `modules/param_fuzzer.py`, `modules/tech_detect.py`

**Work Required:**
- [ ] Finalize `DirFuzzerModule` — common file/directory wordlist fuzzing
  - Use/optimize `payloads/common_paths.json`
  - Implement status code filtering (2xx, 3xx, 4xx)
  - Add response size analysis (detect 404 templates)
  - Handle rate limiting gracefully
  
- [ ] Finalize `ParamFuzzerModule` — parameter discovery
  - Use/optimize `payloads/common_params.json`
  - Test GET/POST/Cookie parameters
  - Detect parameter reflection in responses
  - Skip known false positives (analytics tracking params)
  
- [ ] Finalize `TechDetectModule` — web technology fingerprinting
  - Use `payloads/tech_signatures.json` (HTTP headers, response body, JavaScript patterns)
  - Detect CMS, frameworks, libraries (WordPress, React, jQuery, etc.)
  - Identify server banners, version numbers
  - Output to structured JSON (name, version, risk level)

**Acceptance Criteria:**
- All three modules pass unit tests in `tests/test_recon_modules.py`
- Modules appear in `--list-modules` output
- Successfully integrate with `--recon-only` CLI flag
- Execute without hanging on slow/unresponsive targets

**Estimated Effort:** 2–3 days

---

### 2.2 Improve Finding Deduplication & Confidence Scoring

**Status:** ✅ Done (2026-10-07) — `Confidence` enum (`certain`/`firm`/`tentative`) on every finding, set per detection path in all 9 modules; dedup keeps the strongest confidence; shown in terminal, Markdown, HTML, and JSON. Cross-endpoint grouping followed in Phase 2 (see 3.0).

**Problems to Solve:**
- Same vulnerability reported multiple times (e.g., XSS in parameter `?search=` across 10 endpoints)
- No distinction between confirmed and theoretical findings
- Missing evidence hierarchy (DOM reflection > response header echo > timing-based)

**Implementation:**
- [ ] Extend `Finding` dataclass with confidence level enum (CONFIRMED, PROBABLE, PLAUSIBLE)
- [ ] Add evidence chain to each finding (list of proof snippets)
- [ ] Implement deduplication by vulnerability type + injection point
  - Group SQLi findings by table/column signature
  - Group XSS findings by DOM context (attribute, script, text node)
  - De-duplicate SSRF findings across endpoints with same backend service
  
- [ ] Add confidence weighting algorithm
  ```python
  CONFIRMED: multiple injection points exploited + proof-of-concept payload
  PROBABLE: canary injection confirmed + response diffing positive
  PLAUSIBLE: signature match only, no execution proof
  ```

- [ ] Filter findings by confidence in Reporter (add `--min-confidence` CLI flag)

**Affected Files:**
- `modules/base.py` — extend `Finding` class
- `core/reporter.py` — deduplication + sorting logic
- `scanner.py` — add CLI flag and filtering

**Acceptance Criteria:**
- Duplicate XSS findings across multiple endpoints merged into single report entry
- Each finding includes confidence level + evidence list
- `--output` report shows (e.g.) "XSS in parameter (CONFIRMED, 3 proof points)"
- `--verbose` output includes full evidence chain

**Estimated Effort:** 2–3 days

---

### 2.3 Enhanced Result Filtering & Suppression Rules

**Status:** ✅ Done (2026-10-07) — `core/filters.py`, `--min-severity`, `--min-confidence`, `--suppress FILE` (`suppress.example.yaml`). Filtered findings are excluded from the CI exit code; invalid rule files fail before the scan starts. Note: the flag is `--min-severity LEVEL` rather than the list-style `--severity` sketched below.

**Problems to Solve:**
- False positives from reflected error messages, debug logs
- No way to filter by severity/confidence before report generation
- Hardcoded exclusions difficult to customize per-target

**Implementation:**
- [ ] Add suppression rule file (YAML or JSON)
  ```yaml
  # suppression.yaml
  suppress:
    - type: "xss"
      path_pattern: "^/admin/.*"  # Skip admin pages
    - type: "headers"
      header: "X-Powered-By"      # Known false positive
    - type: "sqli"
      parameter: "csrf_token"     # CSRF tokens trigger SQLi signatures
  ```

- [ ] Add CLI flags for filtering
  ```bash
  vortex -u target.com --severity high,critical
  vortex -u target.com --min-confidence PROBABLE
  vortex -u target.com --suppress suppression.yaml
  ```

- [ ] Implement finding filtering in Reporter
  - Load suppression rules at scan time
  - Apply before report generation
  - Log suppressed findings in verbose mode

**Affected Files:**
- `core/reporter.py` — add filtering logic
- `scanner.py` — add CLI flags
- Add new file: `config/suppression.yaml.example`

**Acceptance Criteria:**
- Suppression rules applied before report generation
- CLI flags work as documented
- `--verbose` shows "suppressed: 5 findings (X, Y, Z)"

**Estimated Effort:** 1–2 days

---

## 3. Medium-Impact Improvements (Phase 2 — Months 1–2)

### 3.1 Extend Scanner Coverage — New Vulnerability Modules

**Current Modules:** XSS, SQLi, SSRF, Path Traversal, CSRF, Headers Audit (6 total)

**OWASP Top 10 Gaps:**
- ❌ **A01:2021 – Broken Access Control** — Need crawler mode comparison (auth vs. no-auth)
- ❌ **A04:2021 – Insecure Deserialization** — Java/.NET object injection patterns
- ❌ **A03:2021 – Injection** — Template Injection (Jinja2, Handlebars), NoSQL, LDAP
- ❌ **A05:2021 – Cryptographic Failures** — Check for HTTP (non-HTTPS), weak ciphers, mixed content
- ⚠️ **A06:2021 – Vulnerable Dependencies** — Fingerprint library versions in JavaScript
- ❌ **A07:2021 – Identification & Auth Failures** — Weak password policies, session fixation

**Priority New Modules (recommended order):**

#### 3.1.1 Template Injection Module
**Status:** ✅ Done (2026-10-08) — `modules/template_injection.py` (`template_injection`). Injects benign arithmetic polyglots (Jinja2/Twig/Nunjucks, FreeMarker/Thymeleaf, Velocity, Smarty/Mako, ERB/EJS, Razor) into GET params and POST form fields. Reports HIGH/`firm` only when the engine returns the *computed* product (marker-wrapped `191*7=1337`) and it is absent from the baseline; literal un-evaluated reflection is ignored to avoid overlap with XSS false positives. 11 unit tests. **Not done:** header injection vectors, and logic-less engines (Handlebars) which don't evaluate arithmetic.

**File:** `modules/template_injection.py`
- Detect Jinja2, Handlebars, Django, ERB payloads
- Test in query parameters, form fields, headers
- Response diffing to detect expression evaluation
- **Effort:** 2–3 days

#### 3.1.2 NoSQL Injection Module
**Status:** ✅ Done (2026-10-08) — `modules/nosql_check.py` (`nosql_check`). Two signals: (1) error-based — appends boundary strings to a value and matches new MongoDB/CouchDB/generic parser errors → HIGH/`firm`; (2) operator-injection differential — rewrites the parameter key into `param[$ne]` (always-true) vs `param[$eq]` (always-false) and flags a significant response-length delta that also differs from the baseline → MEDIUM/`tentative`. Only comparison operators are sent (no `$where`/`$out`/mutating ops). 11 unit tests. **Not done:** Firebase-specific patterns, JSON-body (`application/json`) operator injection.

**File:** `modules/nosql_check.py`
- MongoDB, CouchDB, Firebase payload patterns
- JSON/BSON injection into query parameters
- Response analysis for query logic bypass
- **Effort:** 2–3 days

#### 3.1.3 Broken Access Control Module
**Status:** ✅ Done (2026-10-08) — `modules/access_control_check.py` (`access_control_check`). Implemented at the module level (no crawler refactor): (1) when auth is configured on the requester (cookies / `Authorization` / HTTP auth), sensitive-path endpoints are re-requested through a credential-stripped `Requester` clone; identical 200 content for the anonymous request → HIGH/`firm`, while 401/403, a login-page body, or a redirect to login is treated as correctly protected; (2) numeric object-reference params are incremented/decremented and a differing, comparable-size 200 response → MEDIUM/`tentative` IDOR. Sensitive-path / login / IDOR-name heuristics live in `payloads/access_control.json`; GET-only, thread-safe origin+path dedup. 18 unit tests. **Not done:** true dual-mode crawl (endpoint-list diffing), role-vs-role (vertical) comparison, and non-numeric/UUID object references.

**File:** `modules/access_control_check.py`
- Run crawler in both authenticated + unauthenticated modes
- Compare endpoint lists (leaked endpoints in no-auth mode)
- Test authorization bypass (switch user ID parameters)
- **Effort:** 3–4 days (requires crawler refactoring)

#### 3.1.4 Cryptographic Failures Module
**Status:** ✅ Done (2026-10-07) as `modules/transport_check.py` — cleartext-HTTP site, password forms over HTTP (HIGH), active vs. passive mixed content, and HTTP→HTTPS redirect check (default ports only). All passive, `certain` confidence. **Not done:** TLS protocol/cipher inspection — needs a raw TLS handshake rather than `requests`.

**File:** `modules/crypto_check.py`
- Detect mixed HTTP/HTTPS content
- Flag weak SSL/TLS versions (if proxy inspection available)
- Check for unencrypted sensitive data in queries/forms
- **Effort:** 1–2 days

**Acceptance Criteria for Each:**
- Module appears in `--list-modules`
- Unit tests with mocked responses
- Handles slow/unresponsive targets gracefully
- Documented payload sources + false positive rates

**Total Effort:** 8–13 days

---

### 3.0 Cross-URL Grouping & Detection Accuracy (done 2026-10-07)

- Findings are grouped by origin + path instead of exact URL, so payloads and query strings no longer split one issue into many; all affected URLs are listed in every report format.
- Cookie-flag and CSRF findings are grouped per origin (`dedup_scope: origin`); cookie findings now carry the cookie name as `parameter`. **Fixed bug:** two different cookies on one page were previously merged into a single finding.
- SARIF fingerprints use the same stable location, so alerts survive probe-order changes between runs.
- **Fixed `xss_check` false positives:** reflection is now anchored to the probe marker (previously any extra `<`/`>` in a *different* response — e.g. an error page — counted), and `;`/`/` alone no longer produce HIGH findings on apps that HTML-escape correctly.
- `xss_check` quick mode now continues when the probe marker is reflected at all, matching its documented behaviour, so filtered-but-vulnerable parameters still get the simpler probes.

### 3.2 Performance Optimizations

**Current Bottlenecks:**
- Sequential module execution (crawl, then XSS, then SQLi, ...)
- No endpoint batching (each endpoint scanned independently)
- No result caching (re-crawl on every scan run)
- HTTP session per probe (connection overhead)

**Optimizations:**

#### 3.2.1 Incremental Scan Mode
**Status:** ✅ Done (2026-10-08) — `core/crawl_cache.py` + `--incremental` / `--cache-file` / `--cache-ttl`. The crawl is serialized to JSON (keyed by a hash of target + max_depth + max_endpoints + scope) after every run; `--incremental` reuses it when the key matches and it is within TTL (default 24h). A changed target/scope or an expired entry invalidates it. 9 unit tests.
- [x] Cache crawl results with timestamp + target hash
- [x] Add `--incremental` flag to skip re-crawl if recent cache exists
- [x] Invalidate cache on scope/target change (key hash); **not done:** granular `--excluded-paths` partial invalidation
- **Files:** `core/crawl_cache.py`, `scanner.py`
- **Effort:** 1–2 days

#### 3.2.2 Endpoint Grouping & Batch Analysis
**Status:** ✅ Done (2026-10-08) — `core/endpoint_group.py` + `--group-endpoints`. Collapses endpoints sharing a structural signature (scheme+host+path + sorted query-param names + form signature) to one representative, so value-only duplicates (`/item?id=1..500`) are probed once. Per-module probing across endpoints was already parallel via the orchestrator's ThreadPoolExecutor. 5 unit tests.
- [x] Group endpoints by structural signature (path + param-name set + forms)
- [x] Probes already run in parallel across endpoints (existing ThreadPoolExecutor)
- **Files:** `core/endpoint_group.py`, `scanner.py`
- **Effort:** 2–3 days

#### 3.2.3 HTTP Session Reuse
**Status:** ✅ Already in place — `Requester` uses one `requests.Session` with a pooled `HTTPAdapter` sized to the worker count. No work needed.

- [ ] Use persistent sessions across probes (already in `Requester`, but verify)
- [ ] Connection pooling (HTTPAdapter with max_retries)
- [ ] Keep-Alive headers in crawl + fuzzing phases
- **Files:** `core/requester.py`
- **Effort:** 1 day

#### 3.2.4 Rate Limiting Awareness
**Status:** ✅ Done (2026-10-07) — urllib3 `Retry` absorbs transient 429/5xx. When a 429 (or 503 with `Retry-After`) survives the retries, `Requester` doubles the global request interval (floor 0.2 s even if rate limiting was disabled, cap 2 s), warns once per slowdown, and halves it again after 50 consecutive unthrottled responses until the configured rate is restored. The count is reported as `throttle_events` in scan metadata with an end-of-scan warning.

- [ ] Detect HTTP 429 (Too Many Requests) responses
- [ ] Auto-backoff and retry with exponential delay
- [ ] Notify user if scan slowing down
- **Files:** `core/requester.py`, `scanner.py`
- **Effort:** 1–2 days

**Target Improvement:** 50–70% faster scans on large targets (100+ endpoints)

**Total Effort:** 5–8 days

---

### 3.3 Enhanced Reporting & Output Formats

**Current Formats:** JSON, Markdown, HTML (with interactive features)

**Enhancements:**

#### 3.3.1 SARIF Export
**Status:** ✅ Done (2026-10-07) — `-o report.sarif`; schema-validated in tests against a vendored SARIF 2.1.0 schema; README has a GitHub Actions example.

- [ ] Add SARIF 2.1.0 output format (OASIS standard)
- [ ] Enables GitHub Code Scanning, VS Code integration
- [ ] Map VortexDAST severities to SARIF levels
- **File:** `core/reporter.py` (add `_render_sarif()`)
- **Effort:** 2 days

#### 3.3.2 HTML Report Improvements
- [x] Request replay — per-finding "Reproduce (curl)" block (shell-quoted, with a copy button) added 2026-10-08. A full request/response DevTools-style viewer is **not done** (would need modules to capture raw request/response pairs).
- [x] Interactive finding filtering — severity buttons + search already existed; confidence and module dropdowns (with counts) added 2026-10-07, verified in headless Chrome incl. 390px mobile width
- [x] Remediation snippets per finding — already present: every module sets `remediation`, rendered in a "Remediation Guidance" box
- [ ] Timeline graph of scan progress — **deferred:** requires per-finding timing instrumentation that is not currently collected
- **Files:** `core/reporter.py` (template updates)
- **Effort:** 2–3 days

#### 3.3.3 PDF Export
**Status:** ✅ Done (2026-10-08) — `Reporter.save_pdf()` renders the HTML report to PDF via WeasyPrint; `-o report.pdf` dispatches to it. WeasyPrint is an optional dependency (clear error if missing). 2 unit tests.
- [x] Generate PDF from HTML template (using WeasyPrint)
- [x] Suitable for executive summaries + offline sharing
- **Files:** `core/reporter.py`
- **Effort:** 1 day

#### 3.3.4 Integration with Defect Tracking
**Status:** ✅ Done (2026-10-08) — webhook summary (`--webhook` + `--webhook-format json|slack`, `core/notify.py`) **plus** issue-tracker export (`core/issue_tracker.py`): `--github-repo` (needs `GITHUB_TOKEN`) and `--jira-url`/`--jira-user`/`--jira-project` (needs `JIRA_API_TOKEN`), filtered by `--issue-min-severity`. Issues carry a stable fingerprint marker for best-effort dedup across runs; GitHub export skips already-filed issues via search. 9 webhook + 10 issue-tracker unit tests (mocked HTTP; no live calls).

- [x] Export findings to Jira tickets (with credentials)
- [x] Auto-create GitHub issues from scan results
- [x] Slack/webhook notifications on findings
- **Files:** `core/notify.py`, `core/issue_tracker.py`, `scanner.py`
- **Effort:** 3–4 days

**Total Effort:** 8–10 days

---

### 3.4 Better Documentation & Payloads

**Status:** ✅ Done (2026-10-08) — all four guides written.

- [x] **Payload Documentation** — `payloads/README.md`: table of every payload set, its module, purpose, and false-positive notes; schema conventions and extension steps.
- [x] **Module Developer Guide** — `docs/MODULE_DEVELOPMENT.md`: skeleton, the `run()` contract, detection patterns (baseline/diff, marker reflection, differential), severity/confidence, payload + test conventions.
- [x] **Scanning Methodology Guide** — `docs/SCANNING_GUIDE.md`: how to run, confidence-level interpretation, how each finding type is reached and confirmed, FP reduction, output formats.
- [x] **Integration Guides** — `.github/workflows/scan.yml` (manual-trigger scan + SARIF upload) and `docs/CICD_INTEGRATION.md` (GitHub Actions, GitLab CI, Jenkins, Jira/GitHub issue export).

**Total Effort:** 6–8 days

---

## 4. Technical Debt & Code Quality (Phase 3)

### 4.1 Type Hints & Static Analysis

**Status:** ✅ Done (2026-10-08) — mypy now passes clean: **"Success: no issues found in 28 source files."** Baseline was 22 errors across 5 files; all fixed at the source (no blanket suppressions): BeautifulSoup attribute access coerced to `str` with `Tag` guards (`core/parser.py`, `modules/tech_detect.py`), per-loop signature variables renamed so mypy no longer unions distinct signature dataclasses (`modules/tech_detect.py`), `functools.partial` instead of an un-inferrable lambda (`modules/dir_fuzzer.py`), redundant `or {}` removed on non-None response headers (`modules/transport_check.py`), and two stale `# type: ignore` comments replaced with real `Any` annotations. mypy config lives in `[tool.mypy]` (pyproject.toml); `mypy` runs in CI (`.github/workflows/ci.yml`).

- [x] Add `# type: ignore` only where necessary — none remain in app code; fixes are real
- [x] Run `mypy` in CI/CD pipeline — `.github/workflows/ci.yml` (mypy + pytest on push/PR)
- [x] Clean type-check — 0 errors across core/, modules/, scanner.py
- **Effort:** 2–3 days

**Files:** `core/parser.py`, `modules/tech_detect.py`, `modules/dir_fuzzer.py`, `modules/transport_check.py`, `modules/headers_audit.py`, `modules/csrf_check.py`, `pyproject.toml`, `setup.py`, `.github/workflows/ci.yml`

---

### 4.2 Test Coverage Expansion

**Status:** ✅ Done (2026-10-08) — baseline measured at **88% line coverage** (`pytest --cov=core --cov=modules --cov=scanner`), above the 80% target, across 507 tests. The modules listed below already had coverage (crawler 93%, parser 89%, traversal 85%, ssrf 72%, csrf 97%); Phase 2/3 additions brought the new code (profiles, crawl_cache, endpoint_group, issue_tracker, reporter PDF/repro) under test too. **Lowest remaining:** `issue_tracker` (68%, network branches), `requester` (69%, transport-error branches — now partly covered by resilience tests), `ssrf_check` (72%).

**Target:** 80%+ code coverage — **met (88%)**.

**Effort:** 3–5 days

---

### 4.3 Error Handling & Resilience

**Status:** ✅ Mostly done (2026-10-08) — the resilience foundations were already in place and are now covered by tests (`tests/test_phase3_resilience.py`).

- [ ] Wrap Playwright operations with timeouts + fallback to static crawl — **N/A for now:** dynamic Playwright crawl is still a stub (`--dynamic` logs "not yet implemented"); revisit when it lands.
- [x] Retry logic for failed HTTP calls — already present: `Requester` uses urllib3 `Retry` (429/5xx, exponential `backoff_factor`) plus adaptive throttling.
- [x] Isolate module exceptions — already present: the fuzz loop catches per-endpoint exceptions, logs, and continues (verified by a test mirroring the loop).
- [x] Handle unresponsive targets — `Requester` converts every transport exception (connection/timeout/redirect/other) into `(None, error)` and never raises; modules degrade to `[]` (new parametrized tests).

**Effort:** 2–3 days

**Files:** `core/requester.py`, `scanner.py`, all modules

---

### 4.4 Configuration Management

**Status:** ✅ Done (2026-10-08) — `core/profiles.py` + scanner wiring. Precedence: explicit CLI flag > `VORTEX_*` env var > `--profile` > `config.yaml` > built-in default. 15 unit tests.

- [x] Pre-built scan profiles — `--profile {aggressive,balanced,quiet}` sets `max_depth` / `concurrency` / `rate_limit_rps` (values match the sketch below).
  ```yaml
  aggressive: { max_depth: 5, concurrency: 30, rate_limit: 50 }
  balanced:   { max_depth: 3, concurrency: 10, rate_limit: 5 }
  quiet:      { max_depth: 2, concurrency: 5,  rate_limit: 1 }
  ```
- [x] Environment variable support — `VORTEX_TIMEOUT`, `VORTEX_RATE_LIMIT`, `VORTEX_MAX_DEPTH`, `VORTEX_THREADS`/`VORTEX_CONCURRENCY`, `VORTEX_PROXY`, `VORTEX_USER_AGENT`.
- [x] Config validation — `validate_config()` fails fast with a clear message on bad types (e.g. negative timeout, non-list scope); runs before the scan starts.
- [x] Per-target config overrides — achievable today via `--config config.prod.yaml` (any path loads and is validated); a dedicated per-target merge layer was not added.

**Files:** `core/profiles.py`, `scanner.py`

**Effort:** 2 days

---

## 5. Advanced Features (Phase 4+)

### 5.1 API Mode & Orchestration

**Status:** ✅ Done (2026-10-08) — `core/api.py` (Starlette, the ASGI framework FastAPI is built on — no new heavyweight dep) over a CLI-independent engine (`core/engine.py`). Run with `vortex-api` or `uvicorn core.api:app`; install via the `api` extra. 22 unit tests (Starlette `TestClient`, engine mocked — no live traffic). Docs: `docs/API.md`.

- [x] Web wrapper around a programmatic scan engine (`core/engine.execute_scan`)
- [x] `POST /scan` with target + config JSON (pydantic-validated), `GET /scan/{id}`, `GET /health`, `GET /modules`
- [x] Streaming progress via Server-Sent Events (`GET /scan/{id}/events`)
- [x] Webhook callback on scan completion (`callback_url`, reuses `core.notify`)
- Jobs run in a background thread pool with an in-memory store. **Not done:** persistent job storage and authentication — add before any multi-user/production exposure.

---

### 5.2 Distributed Scanning

**Status:** ⏸ Deferred — requires a message broker (RabbitMQ/Redis), neither of which is available in this environment, so a worker/orchestrator split could not be built or verified. The new `core/engine.execute_scan` is the clean unit a future worker would call. **Effort:** 5–7 days.

- [ ] Worker pool (RabbitMQ or Redis-based)
- [ ] Master orchestrator distributes endpoints to workers
- [ ] Aggregates findings on master node

---

### 5.3 Machine Learning-Based Anomaly Detection

**Status:** ✅ Core done (2026-10-08) — `core/anomaly.py`. Robust statistics (median/MAD **modified z-score**, Iglewicz–Hoaglin threshold 3.5) rather than a trained model — catches the same response outliers (body size, latency, header count) with no training data and no `scikit-learn` (which isn't installed). `ResponseAnomalyDetector.detect()` does a one-shot pass: the bulk defines "normal", the few outliers are flagged. 9 unit tests (incl. masking and zero-spread edge cases). numpy-backed.

- [x] Build a per-feature baseline from normal responses
- [x] Detect outlier response patterns (body size, latency, header count)
- [x] Flag for manual review (`AnomalyResult` with per-feature reasons)
- [ ] **Not done:** wiring the detector into the live scan pipeline as a finding-producing pass (needs the engine to capture per-response features) — the detection core is ready for that follow-up.

---

### 5.4 Interactive Scan Replay & Debugging

**Status:** ⏸ Deferred — a full React/Vue SPA is out of scope for this backend repo and can't be meaningfully tested here. A lightweight form of replay already shipped in Phase 2: the HTML report's per-finding **"Reproduce (curl)"** block (§3.3.2). The new REST API (§5.1) is the natural backend a future SPA would consume. **Effort:** 5–7 days.

- [x] Partial: copy-paste curl reproduction per finding (HTML report)
- [ ] React/Vue frontend, click-to-replay, request/response viewer, manual payload injection

---

## 6. Dependency & Security Considerations

### 6.1 Current Dependencies
- `requests` — HTTP library
- `beautifulsoup4` — HTML parsing
- `playwright` — Browser automation (optional)
- `pyyaml` — Config files
- `rich` — CLI formatting
- `pytest` — Testing

### 6.2 Recommended Additions
- `mypy` — Static type checking
- `ruff` / `black` — Code formatting (add to CI/CD)
- `weasyprint` — PDF export (for 3.3.3)
- `fastapi` — API mode (for 5.1)
- `cryptography` — Weak cipher detection (for new modules)

### 6.3 Security Updates
- [ ] Add dependency scanning to CI/CD (e.g., `pip-audit`)
- [ ] Pin dependency versions in `requirements.txt`
- [ ] Monthly security audit (GitHub Dependabot)

---

## 7. Implementation Roadmap & Prioritization

### Phase 1 (Weeks 1–2) — Foundation
1. ✅ Complete recon modules (dir_fuzzer, param_fuzzer, tech_detect)
2. ✅ Improve finding deduplication & confidence scoring
3. ✅ Add finding suppression rules & filtering

**Rationale:** Stabilizes core scanning functionality; enables subsequent phases.

---

### Phase 2 (Weeks 3–8) — Expansion & Performance
4. ✅ Extend vulnerability coverage (new modules: Template Injection, NoSQL, Access Control)
5. ✅ Performance optimizations (incremental scans, endpoint batching, session reuse)
6. ✅ Enhanced reporting (SARIF, HTML improvements, PDF)
7. ✅ Documentation & payloads

**Rationale:** Broad vulnerability coverage + usability improvements; community readiness.

---

### Phase 3 (Weeks 9–10) — Polish
8. ✅ Type hints + static analysis
9. ✅ Test coverage expansion
10. ✅ Error handling & resilience
11. ✅ Configuration management improvements

**Rationale:** Code quality; production readiness.

---

### Phase 4+ (Ongoing) — Advanced
12. 🔄 API mode & orchestration
13. 🔄 Distributed scanning
14. 🔄 ML anomaly detection
15. 🔄 Interactive replay UI

**Rationale:** Enterprise features; long-term roadmap.

---

## 8. Success Metrics

### By End of Phase 1
- [ ] All 9 scanner modules functional & tested
- [ ] Deduplication reduces report noise by 50%+
- [ ] Suppression rules successfully filter false positives

### By End of Phase 2
- [ ] 12+ vulnerability types detectable (OWASP Top 10 coverage)
- [ ] Scans on 500-endpoint targets complete in <5 minutes (with concurrency=20)
- [ ] SARIF export enables GitHub Code Scanning integration
- [ ] 3+ integration guides published (GitHub Actions, GitLab CI, Jenkins)

### By End of Phase 3
- [ ] 100% type hint coverage
- [ ] 80%+ unit test coverage (pytest)
- [ ] Zero unhandled exceptions in stress tests (slow/unresponsive targets)
- [ ] Pre-built profiles (aggressive/balanced/quiet) reduce config burden

---

## 9. Questions & Decisions Needed

- [ ] **Playwright requirement?** Keep as optional dependency, or make mandatory?
- [ ] **API mode priority?** Enterprise need, or defer to Phase 4?
- [ ] **Payload sources?** Maintain custom sets, or integrate public wordlists (SecLists)?
- [ ] **CI/CD integration:** GitHub Actions first, or multi-platform (GitLab/Jenkins)?
- [ ] **Reporting scope:** Generate findings-only reports, or include remediation workflows?

---

## 10. Contributing Guidelines

For contributors implementing these improvements:

1. **Create a feature branch:** `feature/improve-xss-detection`
2. **Add tests first** (TDD approach)
3. **Update README.md + IMPROVEMENTS.md** with completed work
4. **Run CI checks locally:**
   ```bash
   pytest tests/ -v --cov
   mypy modules/ core/
   ruff check .
   ```
5. **Submit PR** with clear description of improvement + metrics

---

**Document History:**
- 2026-10-07 — Initial roadmap creation
