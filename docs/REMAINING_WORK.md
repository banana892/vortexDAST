# VortexDAST — Remaining Work

**Last updated:** 2026-10-08

Everything on the roadmap (`IMPROVEMENTS.md`) through **Phase 3** is complete, and
the buildable parts of **Phase 4** (REST API, anomaly-detection core) are done.
This document is a focused digest of what is *still open*, why, and what it would
take. It excludes items already shipped.

Current baseline: **549 tests passing**, **mypy clean** (31 source files, gated in CI),
**88% line coverage**, **13 scanner modules**.

---

## 1. Detection coverage (incremental)

These extend existing, working modules — none are blockers.

| Item | Module | Status | Effort |
|------|--------|--------|--------|
| Header injection vectors; logic-less engines (Handlebars/Mustache) | `template_injection` | **Shipped** (header vectors + logic-less engine probes) | S |
| Firebase patterns; JSON-body (`application/json`) operator injection | `nosql_check` | **Shipped** (Firebase regexes + JSON body fuzzing) | M |
| True dual-mode crawl (auth vs no-auth endpoint-list diff); role-vs-role (vertical) checks; UUID/non-numeric object refs | `access_control_check` | Open (needs crawler orchestration changes) | M–L |
| TLS protocol/cipher inspection | `transport_check` | **Shipped** (raw TLS handshake via stdlib `ssl`) | M |

---

## 2. Reporting

| Item | Why it's open | Effort |
|------|---------------|--------|
| Full request/response replay viewer (DevTools-style) in HTML report | Modules don't currently capture raw request/response pairs; needs a capture layer on `Finding` | M |
| Timeline graph of scan progress | No per-finding/per-phase timing is collected yet | S–M |

*(A lightweight replay already shipped: the per-finding "Reproduce (curl)" block.)*

---

## 3. Performance & crawling

| Item | Why it's open | Effort |
|------|---------------|--------|
| Dynamic (Playwright) crawl | `--dynamic` is still a stub that logs "not yet implemented" | L |
| Playwright timeout + fallback-to-static | Blocked on the dynamic crawl above actually existing | S (after dynamic crawl) |
| Granular `--excluded-paths` partial cache invalidation | Incremental cache currently invalidates on any scope/target change (whole-key hash) | S |

---

## 4. Advanced features (Phase 4+)

| Item | Status | Why it's open / notes | Effort |
|------|--------|-----------------------|--------|
| Distributed scanning (worker pool + orchestrator) | Deferred | Needs a message broker (Redis/RabbitMQ) not available in this environment. `core.engine.execute_scan` is the clean unit a worker would call | L |
| Wire anomaly detector into the live scan pipeline | **Shipped** | Features collected per-endpoint and fed into `ResponseAnomalyDetector` in `core/engine.py` | M |
| Interactive replay & debugging SPA | Deferred | A React/Vue frontend is a separate project; the REST API (`core/api.py`) is the backend it would consume | L |
| API: persistent job storage + authentication | **Shipped** | `APIKeyMiddleware` + file-backed atomic `JobStore` in `core/api.py` | M |

---

## 5. Security & dependency hygiene (§6.3)

Completed before release:

- [x] Add dependency scanning to CI (`pip-audit`)
- [x] Pin dependency versions in `requirements.txt`
- [x] Enable GitHub Dependabot for monthly security updates (`.github/dependabot.yml`)

Effort: **S** (mostly CI/config).

---

## 6. Open product decisions (§9)

Not code — decisions that shape the above:

- Playwright: keep optional, or make it a hard dependency?
- Payload sets: maintain custom lists, or integrate public ones (SecLists)?
- API: prioritise for a product, or keep as a local convenience?
- Reporting scope: findings-only, or include remediation-workflow output?

---

## Suggested next steps (highest value first)

1. **Security/dependency hygiene (§5 here)** — small effort, high payoff, unblocks a clean release.
2. **API auth + persistent storage** — the main gap before the API is shareable.
3. **Wire anomaly detection into the pipeline** — the core already exists and is tested.
4. **Detection-coverage extensions** — pick per engagement need (TLS ciphers, NoSQL JSON bodies, etc.).
5. **Dynamic (Playwright) crawl** — the largest single lift; unblocks JS-heavy targets and the Playwright-resilience item.

*Effort key: S = ≤1 day, M = 2–4 days, L = 1 week+.*
