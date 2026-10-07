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

**Status:** ✅ Done (2026-10-07) — `Confidence` enum (`certain`/`firm`/`tentative`) on every finding, set per detection path in all 9 modules; dedup keeps the strongest confidence; shown in terminal, Markdown, HTML, and JSON. Cross-endpoint grouping (one XSS across many URLs) is not done and moves to Phase 2.

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
**File:** `modules/template_injection.py`
- Detect Jinja2, Handlebars, Django, ERB payloads
- Test in query parameters, form fields, headers
- Response diffing to detect expression evaluation
- **Effort:** 2–3 days

#### 3.1.2 NoSQL Injection Module
**File:** `modules/nosql_check.py`
- MongoDB, CouchDB, Firebase payload patterns
- JSON/BSON injection into query parameters
- Response analysis for query logic bypass
- **Effort:** 2–3 days

#### 3.1.3 Broken Access Control Module
**File:** `modules/access_control_check.py`
- Run crawler in both authenticated + unauthenticated modes
- Compare endpoint lists (leaked endpoints in no-auth mode)
- Test authorization bypass (switch user ID parameters)
- **Effort:** 3–4 days (requires crawler refactoring)

#### 3.1.4 Cryptographic Failures Module
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

### 3.2 Performance Optimizations

**Current Bottlenecks:**
- Sequential module execution (crawl, then XSS, then SQLi, ...)
- No endpoint batching (each endpoint scanned independently)
- No result caching (re-crawl on every scan run)
- HTTP session per probe (connection overhead)

**Optimizations:**

#### 3.2.1 Incremental Scan Mode
- [ ] Cache crawl results with timestamp + target hash
- [ ] Add `--incremental` flag to skip re-crawl if recent cache exists
- [ ] Invalidate cache on URL pattern changes (`--excluded-paths`)
- **Files:** `core/crawler.py`, `scanner.py`
- **Effort:** 1–2 days

#### 3.2.2 Endpoint Grouping & Batch Analysis
- [ ] Group endpoints by domain/path prefix
- [ ] Send related probes in parallel (e.g., XSS on 5 endpoints in parallel)
- [ ] Aggregate results by injection point type
- **Files:** `scanner.py` (orchestrator logic)
- **Effort:** 2–3 days

#### 3.2.3 HTTP Session Reuse
**Status:** ✅ Already in place — `Requester` uses one `requests.Session` with a pooled `HTTPAdapter` sized to the worker count. No work needed.

- [ ] Use persistent sessions across probes (already in `Requester`, but verify)
- [ ] Connection pooling (HTTPAdapter with max_retries)
- [ ] Keep-Alive headers in crawl + fuzzing phases
- **Files:** `core/requester.py`
- **Effort:** 1 day

#### 3.2.4 Rate Limiting Awareness
**Status:** ⚠️ Partly in place — urllib3 `Retry` already retries 429/5xx with backoff and honours `Retry-After`. Still missing: telling the user the target is throttling, and slowing the global rate limiter in response.

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
- [ ] Add request/response replay viewer (browser DevTools-style)
- [ ] Interactive finding filtering (by severity, type, confidence)
- [ ] Remediation snippets per finding (e.g., "fix this SQLi with parameterized queries")
- [ ] Timeline graph of scan progress
- **Files:** `core/reporter.py` (template updates)
- **Effort:** 2–3 days

#### 3.3.3 PDF Export
- [ ] Generate PDF from HTML template (using WeasyPrint)
- [ ] Suitable for executive summaries + offline sharing
- **Files:** `core/reporter.py`, add `weasyprint` dependency
- **Effort:** 1 day

#### 3.3.4 Integration with Defect Tracking
- [ ] Export findings to Jira tickets (with credentials)
- [ ] Auto-create GitHub issues from scan results
- [ ] Slack/webhook notifications on high-severity findings
- **File:** `core/reporter.py` (add export adapters)
- **Effort:** 3–4 days

**Total Effort:** 8–10 days

---

### 3.4 Better Documentation & Payloads

**Current State:** README.md + inline docstrings; payload files minimal

**Improvements:**

- [ ] **Payload Documentation**
  - Document each payload file: why it's included, false positive rates, source
  - `payloads/README.md` with table of payload sets + usage
  - **Effort:** 1 day

- [ ] **Module Developer Guide**
  - Template for writing new scanner modules
  - Common patterns: canary injection, response diffing, signature matching
  - **File:** `docs/MODULE_DEVELOPMENT.md`
  - **Effort:** 1–2 days

- [ ] **Scanning Methodology Guide**
  - How to interpret findings (CONFIRMED vs. PLAUSIBLE)
  - Manual exploitation techniques per finding type
  - **File:** `docs/SCANNING_GUIDE.md`
  - **Effort:** 2 days

- [ ] **Integration Guides**
  - GitHub Actions workflow
  - GitLab CI/CD pipeline
  - Jenkins integration
  - **Files:** `.github/workflows/scan.yml`, etc.
  - **Effort:** 2–3 days

**Total Effort:** 6–8 days

---

## 4. Technical Debt & Code Quality (Phase 3)

### 4.1 Type Hints & Static Analysis

**Current State:** Not yet measured — run `mypy` to establish a baseline.

**Issues:**
- `modules/base.py` — underspecified generics
- `core/parser.py` — missing return type hints
- `core/crawler.py` — `Optional[...]` usage inconsistent

**Fix:**
- [ ] Add `# type: ignore` comments only where necessary (with explanation)
- [ ] Run `mypy` in CI/CD pipeline
- [ ] Target: 100% type coverage
- **Effort:** 2–3 days

**Files:** All Python modules

---

### 4.2 Test Coverage Expansion

**Current State:** 359 tests across 10 files covering all modules, crawler, reporter, and concurrency. Line coverage not yet measured — run `pytest --cov` to establish a baseline.

**Missing Tests:**
- [ ] `core/crawler.py` — crawl logic (BFS, scope enforcement)
- [ ] `core/parser.py` — form/link parsing edge cases
- [ ] `modules/traversal_check.py` — path traversal detection
- [ ] `modules/ssrf_check.py` — SSRF signatures
- [ ] `modules/csrf_check.py` — CSRF token handling

**Target:** 80%+ code coverage (use `pytest --cov`)

**Effort:** 3–5 days

---

### 4.3 Error Handling & Resilience

**Current Issues:**
- No timeout handling on headless browser (Playwright)
- Limited retry logic for failed HTTP requests
- Scanner halts on module crash (should isolate per-endpoint)

**Fixes:**
- [ ] Wrap Playwright operations with timeouts + fallback to static crawl
- [ ] Add retry decorator to all HTTP calls (exponential backoff)
- [ ] Isolate module exceptions (log + continue, don't halt scan)
- [ ] Test against unresponsive targets (slow/hung servers)

**Effort:** 2–3 days

**Files:** `core/crawler.py`, `scanner.py`, all modules

---

### 4.4 Configuration Management

**Current State:** `config.yaml` is monolithic; CLI overrides work but not elegant

**Improvements:**
- [ ] Pre-built scan profiles (aggressive, balanced, quiet)
  ```yaml
  profiles:
    aggressive: { max_depth: 5, concurrency: 30, rate_limit: 50 }
    balanced: { max_depth: 3, concurrency: 10, rate_limit: 5 }
    quiet: { max_depth: 2, concurrency: 5, rate_limit: 1 }
  ```

- [ ] Environment variable support (`VORTEX_TIMEOUT=30`)
- [ ] Config file validation (schema checking)
- [ ] Per-target config overrides (e.g., `config.prod.yaml` for production targets)

**Files:** `scanner.py` (config loader), `config/` directory

**Effort:** 2 days

---

## 5. Advanced Features (Phase 4+)

### 5.1 API Mode & Orchestration

**Goal:** REST API for programmatic scan submission (not just CLI)

**Implementation:**
- [ ] FastAPI/Flask wrapper around scan engine
- [ ] Endpoint: `POST /scan` with target + config JSON
- [ ] Streaming progress via Server-Sent Events (SSE)
- [ ] Webhook callbacks on scan completion
- [ ] **Effort:** 3–5 days

---

### 5.2 Distributed Scanning

**Goal:** Scale scanning across multiple machines

**Implementation:**
- [ ] Worker pool (RabbitMQ or Redis-based)
- [ ] Master orchestrator distributes endpoints to workers
- [ ] Aggregates findings on master node
- [ ] **Effort:** 5–7 days

---

### 5.3 Machine Learning-Based Anomaly Detection

**Goal:** Detect novel vulnerabilities via HTTP response anomalies

**Implementation:**
- [ ] Train baseline model on target normal responses
- [ ] Detect outlier response patterns (unusual headers, body size, timing)
- [ ] Flag for manual review
- [ ] **Effort:** 5+ days (ML expertise required)

---

### 5.4 Interactive Scan Replay & Debugging

**Goal:** Web UI for replaying scan payloads, debugging findings

**Implementation:**
- [ ] React/Vue frontend for viewing scan results
- [ ] Click-to-replay functionality (resend probe with payload highlighted)
- [ ] Request/response viewer with syntax highlighting
- [ ] Manual payload injection interface
- [ ] **Effort:** 5–7 days

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
