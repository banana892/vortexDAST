# Writing a VortexDAST Scanner Module

Every scanner module is a subclass of `modules.base.BaseScannerModule`. Modules
are **auto-discovered** — drop a file in `modules/`, subclass the base, set
`name`/`description`, and it appears in `--list-modules` and runs automatically.

## Minimal skeleton

```python
from __future__ import annotations
from typing import Any, List, Optional

from .base import BaseScannerModule, Confidence, Finding, Severity
from core.crawler import CrawledEndpoint


class MyCheckModule(BaseScannerModule):
    name = "my_check"
    description = "One sentence shown in --list-modules."

    def __init__(self, requester: Any, payloads_path: Optional[str] = None) -> None:
        super().__init__(requester)
        # load probes from payloads/ here

    def run(self, endpoint: CrawledEndpoint) -> List[Finding]:
        findings: List[Finding] = []
        # inspect endpoint.query_params, endpoint.forms, endpoint.links
        return findings
```

Then register it in `modules/__init__.py` (import + `__all__`).

## The contract

- `run(endpoint)` is called once per crawled endpoint, possibly from multiple
  threads. Keep per-instance mutable state thread-safe (use a `threading.Lock`,
  as `dir_fuzzer` and `access_control_check` do for their dedup sets).
- **Never create your own HTTP session.** Use `self.requester` so global rate
  limiting, retries, cookies, and auth are honoured. `requester.get()` and
  `requester.post()` return `(response, error)` — always check `error`/`None`.
- Return `Finding` objects; the orchestrator handles dedup, filtering, and
  reporting.

## Common detection patterns

**Baseline → probe → diff.** Fetch the unmodified request first, inject a probe,
then report only signals *absent from the baseline* (used by `sqli_check`,
`nosql_check`). This is the single most effective false-positive guard.

**Marker reflection.** Wrap a unique marker around a payload and look for the
*transformed* marker in the response — e.g. `template_injection` injects
`vtxSSTI{{191*7}}ENDvtx` and only fires on `vtxSSTI1337ENDvtx`, which proves
server-side evaluation rather than mere reflection.

**Differential.** Send an always-true and an always-false variant and compare
responses (`sqli_check` Boolean-blind, `nosql_check` `$ne`/`$eq`). Report on a
meaningful delta; mark these `tentative`.

## Severity & confidence

Set `severity` (`Severity`) from impact and `confidence` (`Confidence`) from how
directly the evidence proves the issue:

- `CERTAIN` — directly observed (missing header, leaked file).
- `FIRM` — strong signal new vs. baseline (DBMS error, evaluated expression).
- `TENTATIVE` — heuristic needing manual review (timing, length delta).

Compute a CVSS vector with `core.cvss.build_vector(...)` and score it with
`core.cvss.calculate(...)`; set both `cvss_vector` and `cvss_score` on the
finding. Put module-specific metadata in `extra` and include `"module": self.name`.

## Payloads

Store probes as JSON in `payloads/` and load them in `__init__` (accept a
`payloads_path` override so tests can point at fixtures). Degrade gracefully: a
missing or malformed file should log and yield an empty probe list, never crash.
See `payloads/README.md`.

## Tests

Add `tests/test_*_<module>.py`. Mock the requester with `MagicMock(spec=Requester)`
and give `.get`/`.post` a `side_effect` returning `(mock_response, None)`. Cover:
metadata, payload loading + missing-file, a true-positive, and at least one
false-positive guard. Confirm discovery with
`assert "my_check" in scanner.MODULE_REGISTRY`.
