# VortexDAST Payload Sets

Every scanner module loads its probes from a JSON file in this directory. Keeping
payloads as data (not code) means they can be audited, extended, or swapped per
engagement without touching the module logic.

All probe sets are **benign by design**: they are built to *reveal* a weakness
(trigger an error, reflect a marker, flip query logic) without carrying a
destructive action (no `DROP`, no OS command execution, no `$out`/`$where` code,
no file writes).

| File | Used by | Purpose | Notes on false positives |
|------|---------|---------|--------------------------|
| `xss_canaries.json` | `xss_check` | Unique reflection markers + context-breaking probes | Reflection is anchored to the marker to avoid matching unrelated `<`/`>` |
| `sqli_probes.json` | `sqli_check` | SQL boundary chars + DBMS error regexes | Error must be *absent from baseline* to count |
| `nosql_probes.json` | `nosql_check` | NoSQL boundary chars, `$ne`/`$eq` operators, driver-error regexes | Operator findings are `tentative`; errors must be new vs. baseline |
| `ssti_probes.json` | `template_injection` | Arithmetic polyglots (`191*7`) per template engine | Only the *computed* result (marker-wrapped) counts, not literal reflection |
| `ssrf_probes.json` | `ssrf_check` | Callback / internal-address probes | — |
| `traversal_probes.json` | `traversal_check` | Path-traversal sequences + file signatures | — |
| `common_paths.json` | `dir_fuzzer` | Sensitive-file / directory wordlist | Soft-404 detection filters catch-all responses |
| `common_params.json` | `param_fuzzer` | Hidden-parameter name wordlist | Second baseline measures natural page jitter |
| `tech_signatures.json` | `tech_detect` | Header / body / JS fingerprints | — |
| `access_control.json` | `access_control_check` | Sensitive-path patterns, login indicators, IDOR param names | Sensitive-path gating keeps public pages from flagging |

## Schema conventions

Each file begins with a `meta` block describing its contents and a `safe: true`
flag. Probe entries carry a stable `id` so findings can reference the exact probe
that fired. Where a module distinguishes confidence levels, the payload file
provides the signals for each (e.g. `sqli_probes.json` separates error regexes
from Boolean-blind probes).

## Extending a payload set

1. Add entries to the relevant JSON file (keep each `id` unique).
2. Prefer markers/operands unlikely to appear naturally in a response to keep the
   false-positive rate low.
3. Run the module's test file (e.g. `pytest tests/test_phase2_nosql.py`).
4. If you add a brand-new file, document it in the table above.

## Using public wordlists

`dir_fuzzer` and `param_fuzzer` accept a custom payload path, so a larger public
set (e.g. SecLists) can be pointed at them without editing the bundled defaults.
