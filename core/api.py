"""
VortexDAST – core/api.py
────────────────────────────────────────────────────────────────────────────
REST API mode (Phase 4 §5.1) — submit scans programmatically over HTTP.

Built on Starlette (the ASGI framework FastAPI is itself built on) so it adds
no new heavyweight dependency. Scans run in a background thread pool; results
are polled or streamed via Server-Sent Events, and an optional webhook callback
fires on completion.

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
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ValidationError, field_validator
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from core.engine import ScanReport, available_modules, execute_scan
from core.notify import build_payload, send_webhook

logger = logging.getLogger(__name__)

_MAX_WORKERS = 4


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
# Job store
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
    """Thread-safe in-memory job registry."""

    def __init__(self) -> None:
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def create(self, target: str) -> ScanJob:
        job = ScanJob(id=uuid.uuid4().hex, target=target)
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def add_event(self, job_id: str, event: Dict[str, Any]) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.events.append(event)


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────


def create_app() -> Starlette:
    store = JobStore()
    pool = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="vdast-api")

    def _run_job(job: ScanJob, req: ScanRequest) -> None:
        job.status = "running"

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
            if req.callback_url:
                _send_callback(req.callback_url, report)
        except Exception as exc:  # noqa: BLE001 — surface failure on the job, not the pool
            logger.exception("scan job %s failed", job.id)
            job.status = "failed"
            job.error = str(exc)
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
    app = Starlette(routes=routes)
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
