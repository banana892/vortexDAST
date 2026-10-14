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
| Static crawl + 17 scanner modules (XSS, SQLi, NoSQLi, SSTI, traversal, SSRF, command injection, open redirect, CORS, file upload, CSRF, access-control, headers, transport, dir/param/tech recon) | ✅ Shipped |
| Reporting: terminal, JSON, HTML, Markdown, SARIF 2.1.0; CVSS v3.1 | ✅ Shipped |
| REST API mode, CI/CD exit codes, webhook notifications | ✅ Shipped |
| Host-scoped TCP port scan + explicit CIDR subnet sweep | ✅ Shipped (opt-in) |
| Form-login auth: CSRF harvesting, multi-step/MFA (TOTP), session recovery | ✅ Shipped |
| **Tool orchestration** — 9 adapters: nuclei, nmap, httpx, ffuf, sqlmap, interactsh, nikto, testssl.sh, subfinder (`--tools`) | ✅ Shipped (opt-in) |
| **Out-of-band (OAST)** testing for blind SSRF, RCE, SQLi and XXE (via interactsh) | ✅ Shipped (opt-in) |
| **JavaScript / SPA rendering** (`--dynamic`, headless Chromium) | ✅ Shipped (opt-in) |
| **JSON API fuzzing** — captures `fetch`/XHR calls during `--dynamic` crawling and fuzzes their (nested) bodies + REST path segments | ✅ Shipped (opt-in, via `--dynamic`) |
| **OpenAPI/Swagger/Postman spec import** (`--openapi`, `--postman`) | ✅ Shipped (opt-in) |

---

## Install

```bash
git clone https://github.com/banana892/vortexDAST.git
cd vortexDAST
pip install -e .            # core scanner + CLI (`vortex` / `vortexdast`)
pip install -e ".[api]"     # optional: REST API mode (`vortex-api`)
playwright install chromium # optional: needed only for --dynamic (SPA crawl)
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

Authenticated scan (form login, with mid-scan session recovery; a per-session
CSRF token on the login page is harvested and submitted automatically):

```bash
vortex -u https://app.local/ \
  --login-url https://app.local/login \
  --login-data "username=admin&password=s3cret" \
  --login-success-text "Sign out" \
  --logged-out-text "Please log in"
```

With MFA (a second step after login; `{totp:SECRET}` computes a live RFC 6238
code at submission time and again on every re-auth — a fixed code would
expire):

```bash
vortex -u https://app.local/ \
  --login-url https://app.local/login \
  --login-data "username=admin&password=s3cret" \
  --mfa-url https://app.local/mfa \
  --mfa-data "otp={totp:JBSWY3DPEHPK3PXP}" \
  --mfa-success-text "Sign out" \
  --logged-out-text "Please log in"
```

OAuth2/OIDC-protected target (exchanges credentials for a bearer access
token at the authorization server's token endpoint and attaches it to every
request; mutually exclusive with `--login-url`). `client_credentials` is a
service-level client id/secret, no end-user account:

```bash
vortex -u https://api.app.local/ \
  --oauth2-token-url https://idp.local/oauth/token \
  --oauth2-client-id my-client \
  --oauth2-client-secret s3cret
```

`password` (Resource Owner Password Credentials) exchanges a test account's
own username/password instead — and either grant transparently refreshes the
token mid-scan once it expires or the resource server rejects it:

```bash
vortex -u https://api.app.local/ \
  --oauth2-token-url https://idp.local/oauth/token \
  --oauth2-grant-type password \
  --oauth2-client-id my-client \
  --oauth2-username bob --oauth2-password s3cret
```

`authorization_code` (+ PKCE, RFC 7636) is the interactive grant: a real
headless Chromium (bundled with the dynamic-crawl dependency) is driven
through the identity provider's own login page, filling `--oauth2-login-data`
into the rendered form and submitting it, then the authorization code is
read out of the server's redirect back to `--oauth2-redirect-uri` — which
never needs to resolve to anything real — and exchanged for a token with the
PKCE verifier:

```bash
vortex -u https://api.app.local/ \
  --oauth2-token-url https://idp.local/oauth/token \
  --oauth2-grant-type authorization_code \
  --oauth2-client-id my-client \
  --oauth2-authorize-url https://idp.local/oauth/authorize \
  --oauth2-redirect-uri https://app.local/callback \
  --oauth2-login-data "username=bob&password=s3cret"
```

Role matrix (opt-in; logs in a *second* identity with the same login
mechanism and diffs what each can reach — surfaces vertical privilege
escalation on sensitive paths and, for any object-reference parameter,
direct horizontal access to the primary identity's own object):

```bash
vortex -u https://app.local/ \
  --login-url https://app.local/login \
  --login-data "username=admin&password=s3cret" \
  --role2-login-data "username=lowpriv&password=s3cret"
```

OAuth2 has the same role matrix: reuse the primary identity's token endpoint/
grant/scope and override only the identity-bearing field(s) —
`--role2-oauth2-client-id` + `--role2-oauth2-client-secret` for
`client_credentials`, `--role2-oauth2-username` + `--role2-oauth2-password`
for `password`, `--role2-oauth2-login-data` for `authorization_code`:

```bash
vortex -u https://api.app.local/ \
  --oauth2-token-url https://idp.local/oauth/token \
  --oauth2-client-id admin-svc --oauth2-client-secret s3cret \
  --role2-oauth2-client-id lowpriv-svc --role2-oauth2-client-secret s3cret
```

JS-rendered SPA (opt-in; headless Chromium renders each page before the
crawler extracts links/forms — closes modern SPAs that show nothing to a
plain HTTP GET):

```bash
vortex -u https://app.local --dynamic
```

`--dynamic-workers N` (default 1) renders up to `N` pages concurrently —
each is a whole separate headless Chromium process, so raise it only once
the dynamic-crawl phase is actually the bottleneck on a large SPA:

```bash
vortex -u https://app.local --dynamic --dynamic-workers 4
```

API testing (opt-in; import endpoints from a spec instead of/alongside
crawling — every path is rebased onto `-u`'s target, request bodies are
fuzzed the same way a captured `--dynamic` JSON request is):

```bash
vortex -u https://app.local --openapi openapi.yaml
vortex -u https://app.local --postman collection.json
```

Network recon (opt-in; scans the target host, or an explicit range):

```bash
vortex -u https://app.local --port-scan
vortex -u https://app.local --subnet 192.168.1.0/24 --ports 22,80,443,3306
```

Orchestrate external tools (opt-in; each is optional and auto-detected):

```bash
vortex --list-tools                               # adapters + install state
vortex -u https://app.local --tools nuclei        # add nuclei's template checks
vortex -u https://app.local --tools nmap,httpx    # recon: ports + live HTTP
vortex -u https://app.local --tools ffuf --ffuf-wordlist big.txt  # content discovery
vortex -u https://app.local --tools sqlmap        # confirm/exploit SQLi leads
vortex -u https://app.local --tools interactsh    # confirm blind SSRF/RCE/SQLi/XXE via OOB callback
vortex -u https://app.local --tools nikto         # web-server misconfig / known-file scan
vortex -u https://app.local --tools testssl       # deep TLS/cipher/cert analysis
vortex -u https://app.local --tools subfinder,httpx  # subdomains + which are live
vortex -u https://app.local --tools all --tool-timeout 300
```

Tool findings are folded into the same report, dedup, filters and CI exit code
as the built-in modules. A missing tool never fails the scan: nmap falls back to
the built-in TCP port scan; the others are skipped with a clear note.

**Data-chaining**: select more than one tool and they actually feed each
other — `nmap`'s discovered open ports and `subfinder`'s discovered
subdomains both get probed by `httpx`, and every URL `httpx` confirms live
gets templated/fuzzed/misconfig-checked/TLS-analysed by
`nuclei`/`ffuf`/`nikto`/`testssl` too, not just the one URL you gave `-u`:

```bash
vortex -u https://app.local --tools nmap,httpx,nuclei,nikto --tool-timeout 600
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
   │                ORCHESTRATION LAYER (--tools)                │
   │   ToolAdapter registry — each wraps an external specialist, │
   │   runs it as a subprocess, parses its JSON/XML, and maps    │
   │   the results into VortexDAST Findings:                     │
   │                                                             │
   │     shipped:  nmap ─ httpx ─ nuclei ─ ffuf ─ sqlmap ─        │
   │               interactsh ─ nikto ─ testssl.sh ─ subfinder    │
   │   (detect-if-installed; built-in fallback when absent)      │
   └───────────────────────────────────────────────────────────┘
```

- **Core** is the web-app scanner: a concurrent crawler, an optional headless-
  Chromium dynamic crawl (`core/dom_watcher.py`, `--dynamic`) that renders JS
  and feeds the same `HTMLParser` the static crawler uses, auto-discovered
  scanner modules (`modules/`), a shared thread-safe `Requester`, and a
  reporter. This is VortexDAST's own depth and is fully implemented.
- **Orchestration layer** (`core/orchestrator.py` + `adapters/`) runs
  `ToolAdapter`s that shell out to external tools — always as an argv list with
  `shell=False` and a hard timeout — and translate their output into the same
  `Finding` objects, so one scan and one report span network recon through
  web-app testing. Adapters are auto-discovered: drop a file in `adapters/`,
  subclass `ToolAdapter`, set `name` + `binary`. See
  [`IMPROVEMENTS.md`](IMPROVEMENTS.md).

---

## CLI reference (today)

```text
usage: vortexdast [-h] [--list-modules] [--list-tools] [--list-themes]
                  [--theme NAME] [--no-color] [--target URL] [--max-depth N]
                  [--modules MODULES] [--recon-only]
                  [--port-scan] [--ports LIST] [--port-scan-timeout SECS]
                  [--subnet CIDR] [--max-subnet-hosts N] [--subnet-workers N]
                  [--tools LIST] [--no-tools] [--tool-timeout SECS]
                  [--ffuf-wordlist FILE]
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
  recovery), `--no-csrf-harvest` (disable hidden-field harvesting), `--mfa-url`
  + `--mfa-data` + `--mfa-method` + `--mfa-success-text` + `--mfa-failure-text`
  (multi-step/MFA, with `{totp:SECRET}` for a live code), `--role2-login-data`
  (role-matrix: a second identity via the same login mechanism),
  `--oauth2-token-url` + `--oauth2-grant-type` + `--oauth2-client-id` +
  `--oauth2-client-secret` + `--oauth2-username` + `--oauth2-password` +
  `--oauth2-scope` (OAuth2/OIDC bearer-token auth — `password` or
  `client_credentials`; mutually exclusive with `--login-url`), plus
  `--oauth2-authorize-url` + `--oauth2-redirect-uri` + `--oauth2-login-data`
  for `--oauth2-grant-type authorization_code` (+ PKCE, browser-driven),
  `--role2-oauth2-username`/`-password` + `--role2-oauth2-client-id`/`-secret`
  + `--role2-oauth2-login-data` (role-matrix: a second OAuth2 identity,
  reusing the primary's token endpoint/grant/scope)
- **Network recon (opt-in):** `--port-scan`, `--ports`, `--subnet`,
  `--max-subnet-hosts`, `--subnet-workers`
- **External tools (opt-in):** `--tools` (`all` or a comma list, e.g.
  `nuclei,nmap,httpx,ffuf,sqlmap,interactsh,nikto,testssl,subfinder`), `--no-tools` (force built-ins only), `--tool-timeout`
  (hard per-tool cap, default 600 s), `--ffuf-wordlist`, `--list-tools`. Tools
  that send HTTP (ffuf) honour `--rate-limit`, `--threads`, `--cookie` and `-H`
- **Throughput:** `--rate-limit`, `--threads/--concurrency`, `--timeout`,
  `--proxy`, `--insecure`
- **Output / filtering:** `--output/-o` (`.json/.sarif/.md/.html`),
  `--min-severity`, `--min-confidence`, `--suppress`, `--verbose`
- **Presentation:** `--theme`, `--list-themes`, `--no-color`

> **Note:** `--dynamic` (headless-Chromium SPA crawl) is a real feature, not a
> stub — see the dynamic-crawl example below. It's additive to the static
> crawl and needs the browser binary: `playwright install chromium`.

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
