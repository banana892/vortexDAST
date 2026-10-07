# Scanning Methodology & Interpreting Results

This guide explains how to run a useful scan and how to read what comes back.

## Before you scan

Only scan targets you are authorised to test. For anything beyond a local lab,
have written permission and stay within the agreed scope.

A typical run:

```bash
vortex -u https://target.example.com -o report.html
```

Useful flags:

- `--cookie "session=…"` / `--header "Authorization: Bearer …"` — scan as a
  logged-in user. This also enables `access_control_check`'s auth-strip test.
- `--max-depth`, `--max-endpoints` — bound the crawl.
- `--rate-limit` — be polite; the scanner also auto-backs-off on HTTP 429.
- `--incremental` — reuse a recent cached crawl for the same target/scope.
- `--group-endpoints` — collapse value-only duplicate endpoints on large sites.
- `--min-severity` / `--min-confidence` / `--suppress rules.yaml` — cut noise.

## Confidence levels

Confidence tells you how much manual verification a finding needs:

| Level | Meaning | What to do |
|-------|---------|------------|
| `certain` | Directly observed fact (missing header, leaked file) | Treat as true; prioritise by severity |
| `firm` | Strong signal new vs. baseline (DBMS error, evaluated template expression) | Very likely real; confirm the exploit path |
| `tentative` | Heuristic (timing, response-length delta, IDOR swap) | **Manually verify before reporting** |

Severity reflects impact (CVSS); confidence reflects certainty. A `tentative`
critical still needs a human to confirm it is real.

## How each finding is reached (and how to confirm it)

- **Reflected XSS** — a unique marker was reflected unescaped in an executable
  context. Confirm by loading the URL and checking the payload executes.
- **SQL injection** — a boundary char produced a *new* DBMS error, or true/false
  conditions changed the response length. Confirm with a careful manual probe.
- **NoSQL injection** — a new driver error, or `[$ne]` vs `[$eq]` changed the
  result set. Confirm the operator reaches the query.
- **Template injection (SSTI)** — an arithmetic expression was evaluated
  server-side (the product appeared in the response). Confirm, then assess RCE
  reachability for the specific engine.
- **Broken access control** — a sensitive page returned identical content with
  credentials stripped (exposure), or swapping a numeric ID returned a different
  record (potential IDOR). Confirm ownership of the records.
- **Transport / headers** — passive observations; verify against policy.

## Reducing false positives

1. Scan authenticated where relevant so protected pages behave normally.
2. Add a `--suppress` file for known-safe parameters/paths (see
   `suppress.example.yaml`).
3. Raise `--min-confidence` to `firm` to hide heuristic findings during triage.

## Output formats

`-o` dispatches on the extension: `.json`, `.sarif`, `.md`, `.html`, `.pdf`.
Use `.sarif` for GitHub Code Scanning (see `docs/` CI examples), `.html`/`.pdf`
for human review, `.json` for further processing.
