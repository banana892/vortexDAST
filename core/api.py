"""
VortexDAST – core/api.py
────────────────────────────────────────────────────────────────────────────
REST API mode (Phase 4 §5.1) — submit scans programmatically over HTTP.

Built on Starlette (the ASGI framework FastAPI is itself built on) so it adds
no new heavyweight dependency. Scans run in a background thread pool; results
are polled or streamed via Server-Sent Events, and an optional webhook callback
fires on completion.

Authentication
--------------
When the ``VORTEX_API_KEY`` environment variable is set, every request must
include a matching ``Authorization: Bearer <key>`` header (or ``X-API-Key``
header).  When the env var is unset, auth is disabled (local development).

Storage
-------
By default jobs are kept in memory.  Set ``VORTEX_JOBS_DIR`` to a directory
path to enable JSON-file-backed persistent storage that survives restarts.

Endpoints
---------
    GET  /health                 — liveness + registered module list
    GET  /modules                — available scanner modules
    POST /scan                   — submit a scan; returns a scan id
    GET  /scan/{id}              — scan status + results when done
    GET  /scan/{id}/events       — Server-Sent Events progress stream

Run with::

    uvicorn core.api:app
    # or: python -m core.api  (honours HOST / PORT env vars)

Only scan targets you are authorised to test.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ValidationError, field_validator
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from core.engine import ScanReport, available_modules, execute_scan
from core.notify import build_payload, send_webhook

logger = logging.getLogger(__name__)

_MAX_WORKERS = 4


# ─────────────────────────────────────────────────────────────────────────────
# API-key authentication middleware
# ─────────────────────────────────────────────────────────────────────────────


class APIKeyMiddleware:
    """
    ASGI middleware that enforces Bearer-token or X-API-Key authentication.

    When ``api_key`` is ``None`` (env var unset), all requests are allowed
    (local-dev mode). Otherwise the request must carry a matching key.
    """

    # Paths that never require authentication.
    _PUBLIC_PATHS = frozenset({"/health"})

    def __init__(self, app: ASGIApp, api_key: Optional[str] = None) -> None:
        self.app = app
        self.api_key = api_key

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.api_key is None:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in self._PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return

        # Extract token from headers.
        headers = dict(scope.get("headers", []))
        token = _extract_token(headers)
        if not token or not secrets.compare_digest(token, self.api_key):
            response = JSONResponse(
                {"error": "unauthorized", "detail": "Invalid or missing API key."},
                status_code=401,
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


def _extract_token(headers: Dict[bytes, bytes]) -> Optional[str]:
    """Extract API key from Authorization: Bearer or X-API-Key header."""
    # Try Authorization: Bearer <token>
    auth = headers.get(b"authorization", b"").decode("utf-8", errors="replace")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    # Try X-API-Key
    api_key = headers.get(b"x-api-key", b"").decode("utf-8", errors="replace")
    if api_key:
        return api_key.strip()
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Request model
# ─────────────────────────────────────────────────────────────────────────────


class ScanRequest(BaseModel):
    """Validated body for ``POST /scan``."""

    target: str
    modules: Optional[List[str]] = None
    max_depth: int = Field(default=2, ge=0, le=10)
    max_endpoints: int = Field(default=50, ge=1, le=5000)
    threads: int = Field(default=8, ge=1, le=50)
    rate_limit_rps: float = Field(default=5.0, ge=0)
    callback_url: Optional[str] = None

    @field_validator("target", "callback_url")
    @classmethod
    def _must_be_http(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("must be an http:// or https:// URL")
        return v


# ─────────────────────────────────────────────────────────────────────────────
# Job store — in-memory with optional JSON-file persistence
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class ScanJob:
    id: str
    target: str
    status: str = "queued"  # queued | running | completed | failed
    created_at: float = field(default_factory=time.time)
    events: List[Dict[str, Any]] = field(default_factory=list)
    report: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def public(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "created_at": self.created_at,
        }
        if self.report is not None:
            data["result"] = self.report
        if self.error is not None:
            data["error"] = self.error
        return data


class JobStore:
    """Thread-safe in-memory job registry with optional file persistence."""

    def __init__(self, persist_dir: Optional[str] = None) -> None:
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._persist_dir: Optional[Path] = None
        if persist_dir:
            self._persist_dir = Path(persist_dir)
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            self._load_persisted_jobs()

    def _load_persisted_jobs(self) -> None:
        """Load previously saved jobs from disk on startup."""
        if self._persist_dir is None:
            return
        for path in self._persist_dir.glob("*.json"):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                job = ScanJob(
                    id=data["id"],
                    target=data["target"],
                    status=data.get("status", "failed"),
                    created_at=data.get("created_at", 0.0),
                    events=data.get("events", []),
                    report=data.get("report"),
                    error=data.get("error"),
                )
                self._jobs[job.id] = job
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to load persisted job %s: %s", path.name, exc)

    def _persist(self, job: ScanJob) -> None:
        """Write a single job to disk (called under lock)."""
        if self._persist_dir is None:
            return
        path = self._persist_dir / f"{job.id}.json"
        try:
            data = {
                "id": job.id,
                "target": job.target,
                "status": job.status,
                "created_at": job.created_at,
                "events": job.events,
                "report": job.report,
                "error": job.error,
            }
            tmp_path = path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, default=str)
            tmp_path.replace(path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to persist job %s: %s", job.id, exc)

    def create(self, target: str) -> ScanJob:
        job = ScanJob(id=uuid.uuid4().hex, target=target)
        with self._lock:
            self._jobs[job.id] = job
            self._persist(job)
        return job

    def get(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job: ScanJob) -> None:
        """Persist the current state of a job."""
        with self._lock:
            self._persist(job)

    def add_event(self, job_id: str, event: Dict[str, Any]) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.events.append(event)
                self._persist(job)


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────


def create_app(
    *,
    api_key: Optional[str] = None,
    persist_dir: Optional[str] = None,
) -> Starlette:
    """
    Build the VortexDAST Starlette ASGI app.

    Parameters
    ----------
    api_key : str | None
        When set, all non-public endpoints require ``Authorization: Bearer <key>``
        or ``X-API-Key: <key>``.  Defaults to the ``VORTEX_API_KEY`` env var.
    persist_dir : str | None
        Directory for JSON job persistence.  Defaults to the ``VORTEX_JOBS_DIR``
        env var.  When ``None`` / unset, jobs are in-memory only.
    """
    resolved_key = api_key if api_key is not None else os.environ.get("VORTEX_API_KEY")
    resolved_dir = persist_dir if persist_dir is not None else os.environ.get("VORTEX_JOBS_DIR")

    store = JobStore(persist_dir=resolved_dir)
    pool = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="vdast-api")

    def _run_job(job: ScanJob, req: ScanRequest) -> None:
        job.status = "running"
        store.update(job)

        def hook(phase: str, detail: Dict[str, Any]) -> None:
            store.add_event(job.id, {"phase": phase, **detail})

        try:
            report: ScanReport = execute_scan(
                req.target,
                modules=req.modules,
                max_depth=req.max_depth,
                max_endpoints=req.max_endpoints,
                threads=req.threads,
                rate_limit_rps=req.rate_limit_rps,
                progress=hook,
            )
            job.report = report.to_dict()
            job.status = "completed"
            store.update(job)
            if req.callback_url:
                _send_callback(req.callback_url, report)
        except Exception as exc:  # noqa: BLE001 — surface failure on the job, not the pool
            logger.exception("scan job %s failed", job.id)
            job.status = "failed"
            job.error = str(exc)
            store.update(job)
            store.add_event(job.id, {"phase": "failed", "error": str(exc)})

    async def health(request: Request) -> JSONResponse:
        return JSONResponse({
            "status": "ok",
            "service": "vortexdast",
            "modules": available_modules(),
        })

    async def modules(request: Request) -> JSONResponse:
        return JSONResponse({"modules": available_modules()})

    async def submit_scan(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)
        try:
            req = ScanRequest(**body)
        except ValidationError as exc:
            detail = [
                {"field": ".".join(str(p) for p in e["loc"]), "message": e["msg"]}
                for e in exc.errors(include_url=False, include_context=False)
            ]
            return JSONResponse({"error": "validation failed", "detail": detail}, status_code=422)

        job = store.create(req.target)
        pool.submit(_run_job, job, req)
        return JSONResponse(
            {"id": job.id, "status": job.status, "target": job.target},
            status_code=202,
        )

    async def scan_status(request: Request) -> JSONResponse:
        job = store.get(request.path_params["job_id"])
        if job is None:
            return JSONResponse({"error": "scan not found"}, status_code=404)
        return JSONResponse(job.public())

    async def scan_events(request: Request) -> Response:
        job_id = request.path_params["job_id"]
        job = store.get(job_id)
        if job is None:
            return JSONResponse({"error": "scan not found"}, status_code=404)

        async def event_stream() -> Any:
            sent = 0
            # Stream progress events until the job reaches a terminal state.
            while True:
                current = store.get(job_id)
                if current is None:
                    break
                while sent < len(current.events):
                    yield f"data: {json.dumps(current.events[sent])}\n\n"
                    sent += 1
                if current.status in ("completed", "failed"):
                    yield f"data: {json.dumps({'phase': current.status})}\n\n"
                    break
                await asyncio.sleep(0.1)

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    routes = [
        Route("/health", health, methods=["GET"]),
        Route("/modules", modules, methods=["GET"]),
        Route("/scan", submit_scan, methods=["POST"]),
        Route("/scan/{job_id}", scan_status, methods=["GET"]),
        Route("/scan/{job_id}/events", scan_events, methods=["GET"]),
    ]

    app = Starlette(
        routes=routes,
        middleware=[Middleware(APIKeyMiddleware, api_key=resolved_key)],
    )
    app.state.store = store
    return app


def _send_callback(url: str, report: ScanReport) -> None:
    """POST a completion summary to the caller's webhook (never raises)."""
    try:
        payload = build_payload(
            report.findings, report.target, "json", 0, report.metadata
        )
        send_webhook(url, payload)
    except Exception as exc:  # noqa: BLE001
        logger.warning("scan callback to %s failed: %s", url, type(exc).__name__)


app = create_app()


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:  # pragma: no cover
    import uvicorn  # noqa: PLC0415

    uvicorn.run(app, host=host, port=port)


def _cli() -> None:  # pragma: no cover - thin argparse wrapper
    import argparse

    parser = argparse.ArgumentParser(
        prog="vortex-api", description="Run the VortexDAST REST API server."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000).")
    args = parser.parse_args()
    run_server(args.host, args.port)


if __name__ == "__main__":  # pragma: no cover
    _cli()
