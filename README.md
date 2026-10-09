# VortexDAST

**A web-application security scanner with an orchestration layer.**

VortexDAST crawls a target web app, fuzzes its inputs with benign probes, and
reports findings (XSS, SQLi, SSRF, security-header and transport issues, and
more) with CVSS scores, severity, confidence and remediation — as terminal
output or JSON / HTML / SARIF.

Its direction is to become an **orchestrator**: VortexDAST does its own
web-app testing well *and* drives best-of-breed open-source tools
(nmap, nuclei, httpx, sqlmap, …) when they are installed, unifying everything
into one report. One command, one report — powered by the right specialist for
each job, with a built-in fallback when a tool is absent.

> **Only scan targets you own or are explicitly authorised to test.**

---

## Status at a glance

VortexDAST is an actively evolving project. This table is the honest line
between what runs today and what is planned — see
[`IMPROVEMENTS.md`](IMPROVEMENTS.md) for the full roadmap.

| Area | State |
|------|-------|
| Static crawl + 13 scanner modules (XSS, SQLi, NoSQLi, SSTI, traversal, SSRF, CSRF, access-control, headers, transport, dir/param/tech recon) | ✅ Shipped |
| Reporting: terminal, JSON, HTML, Markdown, SARIF 2.1.0; CVSS v3.1 | ✅ Shipped |
| REST API mode, CI/CD exit codes, webhook notifications | ✅ Shipped |
| Host-scoped TCP port scan + explicit CIDR subnet sweep | ✅ Shipped (opt-in) |
| Form-login authentication + mid-scan session recovery | ✅ Shipped (scaffold) |
| **Tool orchestration** (nmap / nuclei / httpx / sqlmap adapters) | 🚧 Planned — Phase A/B |
| **JavaScript / SPA rendering** (`--dynamic` Playwright crawl) | 🚧 Planned — currently a stub |
| **Out-of-band (OAST)** testing for blind vulns | 🚧 Planned (via interactsh) |
| **API / OpenAPI import + JSON-body fuzzing** | 🚧 Planned |

---

## Install

```bash
git clone https://github.com/banana892/vortexDAST.git
cd vortexDAST
pip install -e .            # core scanner + CLI (`vortex` / `vortexdast`)
pip install -e ".[api]"     # optional: REST API mode (`vortex-api`)
```

Python 3.11+ recommended.

Orchestrated tools (nmap, nuclei, httpx, sqlmap, …) are **optional external
programs**. When present on `PATH` VortexDAST uses them; when absent it falls
back to its built-in checks or skips with a clear message. None are required to
run a scan.

---

## Quick start

```bash
vortex --list-modules                        # see every scanner module
vortex -u http://testphp.vulnweb.com         # scan a target (authorised only)
vortex -u https://app.local -o report.html   # write an HTML report
vortex -u https://app.local -m xss_check,sqli_check   # run specific modules
```

Authenticated scan (form login, with mid-scan session recovery):

```bash
vortex -u https://app.local/ \
  --login-url https://app.local/login \
  --login-data "username=admin&password=s3cret" \
  --login-success-text "Sign out" \
  --logged-out-text "Please log in"
```

Network recon (opt-in; scans the target host, or an explicit range):

```bash
vortex -u https://app.local --port-scan
vortex -u https://app.local --subnet 192.168.1.0/24 --ports 22,80,443,3306
```

---

## Architecture

```text
                        [ Target URL / scope ]
                                 │
                                 ▼
   ┌───────────────────────────────────────────────────────────┐
   │                    VORTEXDAST CORE (today)                  │
   │   Crawler → Attack-surface extractor → Scanner modules →    │
   │   Response analysis → Reporter (JSON/HTML/SARIF)            │
   └───────────────────────────────┬───────────────────────────┘
                                    │  shared Finding model + session
                                    ▼
   ┌───────────────────────────────────────────────────────────┐
   │              ORCHESTRATION LAYER (planned, Phase A/B)       │
   │   ToolAdapter registry — each wraps an external specialist, │
   │   runs it as a subprocess, parses its JSON, and maps the    │
   │   results into VortexDAST Findings:                         │
   │                                                             │
   │     nmap ─ httpx ─ nuclei ─ sqlmap ─ interactsh ─ …         │
   │   (detect-if-installed; built-in fallback when absent)      │
   └───────────────────────────────────────────────────────────┘
```

- **Core** is the web-app scanner: a concurrent crawler, auto-discovered
  scanner modules (`modules/`), a shared thread-safe `Requester`, and a
  reporter. This is VortexDAST's own depth and is fully implemented.
- **Orchestration layer** (roadmap) adds `ToolAdapter`s that shell out to
  external tools and translate their output into the same `Finding` objects, so
  one scan and one report span network recon through web-app exploitation. See
  [`IMPROVEMENTS.md`](IMPROVEMENTS.md).

---

## CLI reference (today)

```text
usage: vortexdast [-h] [--list-modules] [--list-themes] [--theme NAME]
                  [--no-color] [--target URL] [--max-depth N]
                  [--modules MODULES] [--recon-only]
                  [--port-scan] [--ports LIST] [--port-scan-timeout SECS]
                  [--subnet CIDR] [--max-subnet-hosts N] [--subnet-workers N]
                  [--rate-limit RPS] [--threads N] [--concurrency N]
                  [--timeout SECS] [--max-endpoints N] [--insecure]
                  [--dynamic] [--config PATH] [--proxy URL] [--cookie STRING]
                  [--header HEADER] [--auth-user USER] [--auth-pass PASS]
                  [--login-url URL] [--login-data FIELDS] [--login-method M]
                  [--login-success-text TEXT] [--login-failure-text TEXT]
                  [--logged-out-text TEXT] [--min-severity LEVEL]
                  [--min-confidence LEVEL] [--suppress FILE] [--output FILE]
                  [--verbose]
```

Key flag groups (run `vortex -h` for the full list):

- **Scope / crawl:** `--target/-u`, `--max-depth`, `--max-endpoints`, `--config`
- **Modules:** `--modules/-m` (`all` or a comma list), `--recon-only`,
  `--list-modules`
- **Auth:** `--cookie`, `--header`, `--auth-user/--auth-pass` (Basic/Digest),
  `--login-url` + `--login-data` (form login), `--logged-out-text` (session
  recovery)
- **Network recon (opt-in):** `--port-scan`, `--ports`, `--subnet`,
  `--max-subnet-hosts`, `--subnet-workers`
- **Throughput:** `--rate-limit`, `--threads/--concurrency`, `--timeout`,
  `--proxy`, `--insecure`
- **Output / filtering:** `--output/-o` (`.json/.sarif/.md/.html`),
  `--min-severity`, `--min-confidence`, `--suppress`, `--verbose`
- **Presentation:** `--theme`, `--list-themes`, `--no-color`

> **Note:** `--dynamic` (Playwright SPA crawl) is a **planned stub** — it logs
> a warning and does not yet render JavaScript. Tracked in `IMPROVEMENTS.md`.

### Terminal themes

Scan output is themed through semantic style tokens, so one flag recolours the
whole UI. Default is **`minimal`** (near-monochrome; colour only for severity
and status). Preview all palettes with `vortex --list-themes`.

```text
--theme flag  >  VORTEX_THEME env  >  config.yaml ui.theme  >  minimal
```

Available: `minimal`, `mono`, `vortex`, `neon`, `matrix`, `dracula`, `nord`,
`solarized`, `gruvbox`. `--no-color` (or `NO_COLOR`/`VORTEX_NO_COLOR=1`) strips
colour while keeping layout.

---

## Findings: severity + confidence

Every finding carries a `confidence` alongside its CVSS-based severity:

| Confidence | Meaning | Examples |
|------------|---------|----------|
| `certain`  | Directly observed | Missing security header, file contents returned, `.env` matched |
| `firm`     | Strong signal absent from baseline | New DBMS error, unencoded XSS reflection, missing CSRF token |
| `tentative`| Heuristic — verify manually | HTTP 500 on probe, boolean-blind length delta, SSRF timing |

Findings removed by `--min-severity`, `--min-confidence` or `--suppress` don't
appear in reports and don't count toward exit code `2`. Run `-v` to see what was
filtered and why. See `suppress.example.yaml` for the rule format.

---

## CI integration (SARIF)

`-o report.sarif` writes a SARIF 2.1.0 log — each finding type becomes a rule
whose `security-severity` is the highest CVSS observed, with stable fingerprints
so alerts track across runs. VortexDAST exits **2** when a HIGH/CRITICAL finding
survives filtering, else **0**, so a pipeline can gate on it.

```yaml
security-scan:
  runs-on: ubuntu-latest
  permissions: { security-events: write }
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with: { python-version: "3.12" }
    - run: pip install -e .
    - run: vortex -u "$STAGING_URL" --min-confidence firm -o vortex.sarif
      env: { STAGING_URL: "${{ vars.STAGING_URL }}" }
      continue-on-error: true   # exit 2 = HIGH/CRITICAL found; still upload
    - uses: github/codeql-action/upload-sarif@v3
      with: { sarif_file: vortex.sarif, category: vortexdast }
```

More in [`docs/CICD_INTEGRATION.md`](docs/CICD_INTEGRATION.md).

---

## Webhook notifications

`--webhook URL` posts a summary when a scan finishes; `--webhook-format slack`
sends a Slack message. It carries severity counts and up to 20 findings (title,
severity, confidence, URL) — never evidence or payloads — and is sent with a
separate HTTP client (scan auth/proxy are not applied to it).

---

## Documentation

- [`IMPROVEMENTS.md`](IMPROVEMENTS.md) — implementation roadmap (the orchestrator plan)
- [`docs/SCANNING_GUIDE.md`](docs/SCANNING_GUIDE.md) — how to run a scan and read results
- [`docs/MODULE_DEVELOPMENT.md`](docs/MODULE_DEVELOPMENT.md) — writing a scanner module
- [`docs/API.md`](docs/API.md) — REST API mode
- [`docs/CICD_INTEGRATION.md`](docs/CICD_INTEGRATION.md) — pipeline integration
- [`payloads/README.md`](payloads/README.md) — probe/payload sets

---

## Legal

VortexDAST is for authorised security testing and education only. Scanning,
port-scanning, or fuzzing systems you do not own or have explicit written
permission to test may be illegal. You are responsible for staying within your
authorised scope. When orchestrating external tools, their licences and terms
apply to your use of them.
