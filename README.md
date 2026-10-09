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
usage: vortexdast [-h] [--list-modules] [--list-themes] [--theme NAME]
                  [--no-color] [--target URL] [--max-depth N]
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
  --list-themes         Print all available colour themes with a live palette
                        preview, then exit with code 0.
  --theme NAME          Terminal colour theme: minimal, mono, vortex, neon,
                        matrix, dracula, nord, solarized, gruvbox. Default:
                        minimal (near-monochrome). Run --list-themes to
                        preview them. Also settable via config.yaml ui.theme
                        or the VORTEX_THEME env var.
  --no-color            Strip all colour from terminal output while keeping
                        the layout. Applies on top of --theme; useful for logs
                        and dumb terminals.
  --target, -u URL      Target base URL to scan (required unless --list-
                        modules). Example: https://target.example.com
  --max-depth N         Crawler BFS recursion depth (default: value from
                        config.yaml, usually 3).
  --modules, -m MODULES
                        Comma-separated list of modules to run, or "all". Run
                        --list-modules to see all available IDs. Default: all
  --recon-only          Run only reconnaissance modules (tech_detect,
                        dir_fuzzer, param_fuzzer). Overrides --modules.
  --port-scan           Enable the TCP connect port scan (opt-in; excluded
                        from --modules all). Scans the target host by default.
  --ports LIST          Comma-separated ports and ranges, e.g.
                        "22,80,8000-8100". Implies --port-scan. Default:
                        curated common-ports list.
  --port-scan-timeout SECS
                        Per-port TCP connect timeout (default: 1.5).
  --subnet CIDR         Sweep an explicit CIDR range instead of just the
                        target host, e.g. "192.168.1.0/24". Implies
                        --port-scan. Only scan ranges you are authorised to
                        test. Host count is capped by --max-subnet-hosts.
  --max-subnet-hosts N  Safety cap on hosts expanded from --subnet (default:
                        1024). A larger range is rejected, not scanned.
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
  vortex -u http://target.com --port-scan
  vortex -u http://target.com --ports 22,80,443,3306,6379,8000-8100
  vortex -u http://target.com --subnet 192.168.1.0/24 --ports 22,80,443,3306
  vortex -u http://target.com --max-endpoints 10 --timeout 5 --rate-limit 10
  vortexdast -u http://target.com --dynamic --verbose
  vortex --list-themes
  vortex -u http://target.com --theme neon
  vortex -u http://target.com --theme mono --no-color -o scan.json
```

### 3.1 Terminal Themes

Scan output is themed. Every colour the CLI prints goes through a semantic
style token (`vortex.accent`, `sev.critical`, …) rather than a hard-coded
colour, so one flag recolours the whole UI — scan header, progress bars,
module table and the findings dashboard.

The default is deliberately plain: **`minimal`** prints no wordmark, uses thin
borders, and carries structure with bold/dim weights. Colour is spent only
where it means something — severity, and success/warning/error. Richer
palettes are opt-in.

```bash
vortex --list-themes                      # preview every palette side by side
vortex -u http://target.local --theme neon
```

| Theme | Font colours |
|---|---|
| `minimal` | **Default.** Near-monochrome; colour only for severity and status |
| `mono` | No colour at all, ASCII borders and marks — best for CI logs |
| `vortex` | Brand palette: violet headings, cyan accents, rounded frames |
| `neon` | High-contrast cyberpunk: magenta, electric cyan, heavy frames |
| `matrix` | Single-hue green terminal, dim through phosphor bright |
| `dracula` | Dracula: purple, pink and soft cyan on dark |
| `nord` | Nord: cool arctic blues with muted accents |
| `solarized` | Solarized Dark: low-glare base tones with warm accents |
| `gruvbox` | Gruvbox: warm retro earth tones, amber and olive |

Themes with a palette also draw a wordmark, framed panels and a themed
spinner; `minimal` and `mono` stay flat and quiet.

Selection follows the project's usual precedence:

```text
--theme flag  >  VORTEX_THEME env  >  config.yaml ui.theme  >  minimal
```

```yaml
# config.yaml
ui:
  theme: minimal     # or mono | vortex | neon | matrix | dracula | nord | solarized | gruvbox
  no_color: false    # strip colour, keep layout (same as --no-color / VORTEX_NO_COLOR=1)
```

`--no-color` (or `VORTEX_NO_COLOR=1`) strips colour from any theme while
keeping the layout intact. The standard `NO_COLOR` environment variable is
honoured by Rich as well.

Without `--verbose`, per-request chatter from the crawler and requester is held
back so the phase lines and dashboard stay readable; `-v` restores the full
DEBUG stream.

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

