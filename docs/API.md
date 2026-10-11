# VortexDAST REST API

Submit scans over HTTP instead of the CLI. The API is built on Starlette and
runs scans in a background thread pool. Install the extra and start the server:

```bash
pip install -e ".[api]"
vortex-api --host 127.0.0.1 --port 8000
# or: uvicorn core.api:app
```

Only scan targets you are authorised to test.

## Authentication

The API **fails closed**. Set `VORTEX_API_KEY` and every request (except
`/health`) must then carry it:

```bash
export VORTEX_API_KEY="$(openssl rand -hex 32)"
vortex-api --port 8000
curl -H "Authorization: Bearer $VORTEX_API_KEY" http://127.0.0.1:8000/modules
# X-API-Key: <key> works too
```

If **no** key is configured, protected endpoints return `503
server_misconfigured` and refuse to run scans. To run without auth (local
development only, on a trusted interface), opt in explicitly with
`--allow-unauthenticated` or `VORTEX_ALLOW_UNAUTHENTICATED=1`. `/health` stays
public in every mode so liveness checks keep working.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/health` | Liveness + registered module list |
| `GET`  | `/modules` | Available scanner modules |
| `POST` | `/scan` | Submit a scan; returns a scan id (HTTP 202) |
| `GET`  | `/scan/{id}` | Scan status, and results once complete |
| `GET`  | `/scan/{id}/events` | Server-Sent Events progress stream |

## Submit a scan

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H 'content-type: application/json' \
  -d '{"target": "https://target.example.com", "max_depth": 2}'
```

Request body (`POST /scan`):

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `target` | string | — | Required; `http://` or `https://` |
| `modules` | string[] | engine default set | Must be registered module names |
| `max_depth` | int | 2 | 0–10 |
| `max_endpoints` | int | 50 | 1–5000 |
| `threads` | int | 8 | 1–50 |
| `rate_limit_rps` | float | 5.0 | ≥ 0 |
| `callback_url` | string | — | Optional webhook POSTed on completion. Must resolve to a public address (SSRF guard); internal targets need `VORTEX_ALLOW_PRIVATE_WEBHOOK=1` on the server |

Response: `202 Accepted` with `{"id": "...", "status": "queued", "target": "..."}`.

## Poll for results

```bash
curl http://127.0.0.1:8000/scan/<id>
```

Returns `status` of `queued` / `running` / `completed` / `failed`. When
`completed`, a `result` object carries the findings and a severity summary.

## Stream progress (SSE)

```bash
curl -N http://127.0.0.1:8000/scan/<id>/events
```

Emits `data: {"phase": "crawl_done", ...}` lines as the scan progresses, ending
with a terminal `completed` / `failed` event.

## Programmatic use

The same engine is callable directly without the HTTP layer:

```python
from core.engine import execute_scan

report = execute_scan("https://target.example.com", max_depth=2)
print(report.metadata, len(report.findings))
```
