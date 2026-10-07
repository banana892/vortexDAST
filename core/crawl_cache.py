"""
VortexDAST – core/crawl_cache.py
────────────────────────────────────────────────────────────────────────────
Incremental-scan support: persist a completed crawl to disk and reload it on a
later run so the (often slow) crawl phase can be skipped.

A cache entry is keyed by a hash of the *scan-defining* inputs (seed URL +
crawl scope). If any of those change, the key changes and the stale entry is
ignored. Entries also carry a timestamp so callers can enforce a freshness TTL.

The on-disk format is plain JSON — every field of :class:`CrawledEndpoint`,
:class:`ParsedForm`, :class:`FormField`, and :class:`ParsedLink` is JSON-safe.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from core.crawler import CrawledEndpoint, CrawlResult
from core.parser import FormField, ParsedForm, ParsedLink

logger = logging.getLogger(__name__)

CACHE_VERSION = 1
DEFAULT_CACHE_PATH = ".vortex_crawl_cache.json"
DEFAULT_TTL_SECONDS = 24 * 3600  # 24 hours


# ─────────────────────────────────────────────────────────────────────────────
# Key derivation
# ─────────────────────────────────────────────────────────────────────────────


def cache_key(seed_url: str, scope: Optional[Dict[str, Any]] = None) -> str:
    """Derive a stable cache key from the scan-defining inputs."""
    payload = {
        "seed": seed_url,
        "scope": _normalise(scope or {}),
        "v": CACHE_VERSION,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _normalise(value: Any) -> Any:
    """Recursively sort collections so key derivation is order-independent."""
    if isinstance(value, dict):
        return {k: _normalise(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple, set)):
        items = [_normalise(v) for v in value]
        try:
            return sorted(items, key=lambda x: json.dumps(x, sort_keys=True))
        except TypeError:
            return items
    return value


# ─────────────────────────────────────────────────────────────────────────────
# (De)serialisation
# ─────────────────────────────────────────────────────────────────────────────


def _field_to_dict(f: FormField) -> Dict[str, Any]:
    return {"name": f.name, "field_type": f.field_type, "default_value": f.default_value}


def _form_to_dict(form: ParsedForm) -> Dict[str, Any]:
    return {
        "action_url": form.action_url,
        "method": form.method,
        "fields": [_field_to_dict(f) for f in form.fields],
    }


def _link_to_dict(link: Any) -> Dict[str, Any]:
    return {
        "url": getattr(link, "url", ""),
        "query_params": getattr(link, "query_params", {}) or {},
    }


def _endpoint_to_dict(ep: CrawledEndpoint) -> Dict[str, Any]:
    return {
        "url": ep.url,
        "status_code": ep.status_code,
        "depth": ep.depth,
        "forms": [_form_to_dict(f) for f in ep.forms],
        "links": [_link_to_dict(l) for l in ep.links],
        "query_params": ep.query_params,
        "response_headers": ep.response_headers,
    }


def serialize_crawl_result(result: CrawlResult) -> Dict[str, Any]:
    """Convert a :class:`CrawlResult` into a JSON-safe dict."""
    return {
        "seed_url": result.seed_url,
        "endpoints": [_endpoint_to_dict(ep) for ep in result.endpoints],
        "failed_urls": result.failed_urls,
    }


def _dict_to_field(d: Dict[str, Any]) -> FormField:
    return FormField(
        name=d.get("name", ""),
        field_type=d.get("field_type", "text"),
        default_value=d.get("default_value", ""),
    )


def _dict_to_form(d: Dict[str, Any]) -> ParsedForm:
    return ParsedForm(
        action_url=d.get("action_url", ""),
        method=d.get("method", "GET"),
        fields=[_dict_to_field(f) for f in d.get("fields", [])],
    )


def _dict_to_link(d: Dict[str, Any]) -> ParsedLink:
    return ParsedLink(
        url=d.get("url", ""),
        query_params=d.get("query_params", {}) or {},
    )


def _dict_to_endpoint(d: Dict[str, Any]) -> CrawledEndpoint:
    return CrawledEndpoint(
        url=d.get("url", ""),
        status_code=d.get("status_code", 0),
        depth=d.get("depth", 0),
        forms=[_dict_to_form(f) for f in d.get("forms", [])],
        links=[_dict_to_link(l) for l in d.get("links", [])],
        query_params=d.get("query_params", {}) or {},
        response_headers=d.get("response_headers", {}) or {},
    )


def deserialize_crawl_result(data: Dict[str, Any]) -> CrawlResult:
    """Rebuild a :class:`CrawlResult` from a serialized dict."""
    return CrawlResult(
        seed_url=data.get("seed_url", ""),
        endpoints=[_dict_to_endpoint(e) for e in data.get("endpoints", [])],
        failed_urls=data.get("failed_urls", {}) or {},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Disk I/O
# ─────────────────────────────────────────────────────────────────────────────


def save_cache(
    path: str,
    key: str,
    result: CrawlResult,
    *,
    now: Optional[float] = None,
) -> None:
    """Write a crawl result to ``path`` under ``key`` with a timestamp."""
    entry = {
        "version": CACHE_VERSION,
        "key": key,
        "created_at": now if now is not None else time.time(),
        "result": serialize_crawl_result(result),
    }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(entry, fh)
        logger.info("Crawl cache written: %s (%d endpoints)", path, len(result.endpoints))
    except OSError as exc:
        logger.warning("Could not write crawl cache %s: %s", path, exc)


def load_cache(
    path: str,
    key: str,
    *,
    ttl_seconds: float = DEFAULT_TTL_SECONDS,
    now: Optional[float] = None,
) -> Optional[CrawlResult]:
    """
    Load a cached crawl result if it exists, matches ``key``, and is fresh.

    Returns ``None`` (never raises) when the cache is missing, corrupt, keyed to
    different inputs, a different cache version, or older than ``ttl_seconds``.
    """
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            entry = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Ignoring unreadable crawl cache %s: %s", path, exc)
        return None

    if entry.get("version") != CACHE_VERSION:
        logger.info("Crawl cache version mismatch — ignoring %s", path)
        return None
    if entry.get("key") != key:
        logger.info("Crawl cache key mismatch (target/scope changed) — ignoring %s", path)
        return None

    created_at = entry.get("created_at", 0)
    current = now if now is not None else time.time()
    age = current - created_at
    if age > ttl_seconds:
        logger.info(
            "Crawl cache stale (%.0fs old > %.0fs TTL) — ignoring %s",
            age, ttl_seconds, path,
        )
        return None

    try:
        result = deserialize_crawl_result(entry["result"])
    except (KeyError, TypeError) as exc:
        logger.warning("Corrupt crawl cache %s: %s", path, exc)
        return None

    logger.info(
        "Crawl cache hit: %s (%d endpoints, %.0fs old)",
        path, len(result.endpoints), age,
    )
    return result
