# Automated Web Vulnerability Scanner (Lightweight DAST Framework)

## 1. Project Overview & Objective
This project is an extensible, lightweight Python-based Dynamic Application Security Testing (DAST) scanner. It maps web application attack surfaces, extracts interactive injection points (forms, parameters, endpoints), fuzzes inputs with benign heuristic probes, and detects common OWASP Top 10 vulnerabilities (including SQL Injection, Reflected Cross-Site Scripting, Missing Security Headers, and SSRF).

Headless browser automation via Playwright ensures coverage of modern Single Page Applications (SPAs) and dynamic DOM manipulations alongside traditional static HTML crawling.

---

## 2. Architecture & Workflow

```text
                      [ Target URL / Scope ]
                                │
                                ▼
    ┌──────────────────────────────────────────────────────┐
    │                 1. CRAWLER & SPIDER                  │
    │  - Static HTTP extraction (BeautifulSoup)            │
    │  - Dynamic DOM rendering & AJAX spider (Playwright)  │
    │  - Scope enforcement (Domain & Subpath whitelist)    │
    └──────────────────────────┬───────────────────────────┘
                               │
                               ▼
    ┌──────────────────────────────────────────────────────┐
    │             2. ATTACK SURFACE EXTRACTOR              │
    │  - Discovered URLs with Query Parameters (?p=...)    │
    │  - Form & Input Parsers (GET/POST, action, fields)   │
    │  - HTTP Headers & Cookie Metadata                    │
    └──────────────────────────┬───────────────────────────┘
                               │
                               ▼
    ┌──────────────────────────────────────────────────────┐
    │             3. HEURISTIC FUZZING ENGINE              │
    │  - Modular vulnerability probes (benign heuristics)  │
    │  - Canary injection & response diffing               │
    │  - Error pattern signatures & response timing        │
    └──────────────┬───────────┬───────────┬───────────────┘
                   │           │           │
          ┌────────┴───┐ ┌─────┴─────┐ ┌───┴──────────┐
          │  modules/  │ │ modules/  │ │   modules/   │
          │  sqli.py   │ │  xss.py   │ │  headers.py  │ ...
          └────────────┘ └───────────┘ └──────────────┘
                               │
                               ▼
    ┌──────────────────────────────────────────────────────┐
    │               4. RESPONSE & DOM ANALYZER             │
    │  - RegEx Signature Matching (DBMS error signatures)  │
    │  - Reflection & Context Breakout Verification        │
    │  - Missing Security Headers & Cookie Flags Audit     │
    └──────────────────────────┬───────────────────────────┘
                               │
                               ▼
    ┌──────────────────────────────────────────────────────┐
    │             5. REPORT GENERATION ENGINE              │
    │  - Structured JSON for CI/CD integration             │
    │  - Human-readable Markdown & HTML summaries          │
    │  - Remediation guidance & CVSS scoring breakdown     │
    └──────────────────────────────────────────────────────┘

## 3. CLI Usage

```text
usage: vortexdast [-h] [--list-modules] [--target URL] [--max-depth N]
                  [--modules MODULES] [--recon-only] [--rate-limit RPS]
                  [--threads N] [--concurrency N] [--timeout SECS]
                  [--max-endpoints N] [--insecure] [--dynamic] [--config PATH]
                  [--proxy URL] [--cookie STRING] [--header HEADER]
                  [--auth-user USER] [--auth-pass PASS] [--min-severity LEVEL]
                  [--min-confidence LEVEL] [--suppress FILE] [--output FILE]
                  [--verbose]

VortexDAST — Lightweight Dynamic Application Security Testing Framework.
Crawls a target web application and runs configurable vulnerability modules.

options:
  -h, --help            show this help message and exit
  --list-modules        Print a Rich table of all registered scanner modules
                        with their IDs and descriptions, then exit with code
                        0.
  --target, -u URL      Target base URL to scan (required unless --list-
                        modules). Example: https://target.example.com
  --max-depth N         Crawler BFS recursion depth (default: value from
                        config.yaml, usually 3).
  --modules, -m MODULES
                        Comma-separated list of modules to run, or "all". Run
                        --list-modules to see all available IDs. Default: all
  --recon-only          Run only reconnaissance modules (tech_detect,
                        dir_fuzzer, param_fuzzer). Overrides --modules.
  --rate-limit RPS      Override requests-per-second rate limit (0 =
                        disabled). Default from config.yaml (usually 5). Safe
                        to raise to 20.0 for authorised remote targets.
  --threads, -t N       Number of concurrent worker threads used by scanner
                        modules. Higher values reduce wall-clock time for
                        probe-heavy modules (XSS, SQLi, SSRF). Default: 10.
                        Recommended range: 5–20. See also: --concurrency
                        (alias that takes precedence).
  --concurrency N       Number of concurrent worker threads (alias for
                        --threads; takes precedence when both are specified).
                        Recommended range: 5–20.
  --timeout SECS        Per-request HTTP timeout in seconds. Overrides the
                        value in config.yaml (usually 10 s). Useful for slow
                        targets (raise to 30) or CI speed (lower to 5).
  --max-endpoints N     Cap the number of crawled endpoints passed to scanner
                        modules. Useful for quick reconnaissance scans (e.g.
                        --max-endpoints 10). Default: unlimited.
  --insecure, -k        Disable SSL certificate verification (for self-signed
                        certs in local labs).
  --dynamic             Enable Playwright headless browser crawling for JS-
                        rendered SPAs. Requires: playwright install chromium
  --config PATH         Path to config.yaml (default:
                        /home/naishring/VortexDAST/config.yaml).
  --proxy URL           HTTP proxy URL (e.g. http://127.0.0.1:8080).
  --cookie, -C STRING   Inject session cookies into every request. Format:
                        "NAME=VALUE; NAME2=VALUE2" (same as a browser Cookie
                        header). Example: --cookie "JSESSIONID=abc123;
                        auth=true"
  --header, -H HEADER   Add a custom HTTP header to every request (may be
                        repeated). Format: "Name: Value". Example: -H
                        "Authorization: Bearer eyJhbG..." -H "X-API-Key:
                        secret"
  --auth-user USER      Username for HTTP Basic / Digest authentication.
  --auth-pass PASS      Password for HTTP Basic / Digest authentication (pair
                        with --auth-user).
  --min-severity LEVEL  Only report findings at or above this severity
                        (critical, high, medium, low, informational).
  --min-confidence LEVEL
                        Only report findings at or above this confidence
                        (certain, firm, tentative). Use 'firm' to hide
                        heuristic hits that need manual verification.
  --suppress FILE       YAML file of suppression rules for known false
                        positives (see suppress.example.yaml).
  --output, -o FILE     Output file for the scan report (.json, .sarif, .md,
                        or .html). If omitted, terminal output only.
  --verbose, -v         Enable verbose DEBUG logging.

Examples:
  vortex --list-modules
  vortex -u http://testphp.vulnweb.com
  vortex -u https://app.local -k -m xss_check,sqli_check
  vortex -u http://target.com --max-depth 2 -o results.json
  vortex -u http://target.com --modules all --rate-limit 20 --concurrency 20
  vortex -u http://target.com --max-endpoints 10 --timeout 5 --rate-limit 10
  vortexdast -u http://target.com --dynamic --verbose
```

## 4. Confidence Levels & Filtering

Every finding carries a `confidence` alongside its severity:

| Confidence | Meaning | Examples |
|------------|---------|----------|
| `certain`  | Directly observed | Missing security header, OS file contents returned, `.env` matched its content signature |
| `firm`     | Strong signal absent from the baseline | New DBMS error string, unencoded XSS reflection, missing CSRF token |
| `tentative`| Heuristic — verify manually | HTTP 500 on probe, boolean-blind length delta, SSRF timing, hidden-param length change |

Findings removed by `--min-severity`, `--min-confidence`, or `--suppress` rules don't appear in reports
and don't count toward exit code `2`. Run with `-v` to see each filtered finding and the reason.
See `suppress.example.yaml` for the rule format.

## 5. CI Integration (SARIF)

`-o report.sarif` (or `.sarif.json`) writes a SARIF 2.1.0 log. Each finding type becomes a rule
(e.g. `dir_fuzzer/exposed-configuration-file`) whose `security-severity` is the highest CVSS score
observed, and each result carries a stable fingerprint so alerts track across runs.

Example GitHub Actions job against a staging deployment:

```yaml
security-scan:
  runs-on: ubuntu-latest
  permissions:
    security-events: write
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with: { python-version: "3.12" }
    - run: pip install -e .
    - run: vortex -u "$STAGING_URL" --min-confidence firm --suppress suppress.yaml -o vortex.sarif
      env: { STAGING_URL: "${{ vars.STAGING_URL }}" }
      continue-on-error: true   # exit code 2 = HIGH/CRITICAL found; let the upload still run
    - uses: github/codeql-action/upload-sarif@v3
      with: { sarif_file: vortex.sarif, category: vortexdast }
```

Only scan targets you own or are authorised to test.

## 6. Webhook Notifications

`--webhook URL` posts a summary when the scan finishes; `--webhook-format slack` sends a Slack
incoming-webhook message instead of the default structured JSON.

- Contains severity counts and up to 20 findings (title, severity, confidence, URL) — never
  evidence or payloads, which can contain leaked secrets.
- Sent with a separate HTTP client: the target's `--cookie`, `--header`, basic-auth, and
  `--proxy` settings are not applied to it.
- A failed post logs a warning (host only — webhook URLs usually embed a token) and does not
  change the exit code.

```bash
vortex -u https://staging.example.com --min-confidence firm \
  --webhook "$SLACK_WEBHOOK_URL" --webhook-format slack
```

