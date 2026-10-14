"""
VortexDAST – core/spec_import.py
────────────────────────────────────────────────────────────────────────────
Import endpoints from an OpenAPI 3.x / Swagger 2.0 spec or a Postman
Collection v2.1 file — local, or fetched directly from a URL — Phase 3 of
the scoped "API testing" work (IMPROVEMENTS.md), the last of three endpoint
sources feeding the same fuzzing engine Phase 1 (``core/dom_watcher.py``'s
passive JSON capture) and Phase 2 (``core/json_fuzz.py``'s leaf/path-segment
fuzzing) already built.

Design
------
A spec file never gets touched for request bodies and path/query parameters
the way a live crawl does — it only has *schemas*, not necessarily literal
example values. So this module's only job is producing the exact same
output Phase 1 already produces: a list of synthetic
:class:`~core.crawler.CrawledEndpoint` (JSON bodies as
:class:`~core.crawler.CapturedJsonRequest`, GET-style operations as plain
``query_params``) — fed into ``scanner.py``'s *existing* dynamic-crawl-style
merge, so the fuzzing engine needs zero changes to consume them.

* OpenAPI 3.x / Swagger 2.0: example values come from the spec's own
  ``example``/``default``/``enum`` where present, else synthesized per JSON
  Schema ``type``. ``allOf`` is merged (every subschema, plus the schema's
  own type/properties if it declares both at once); ``oneOf``/``anyOf``
  pick the first listed variant as the one representative shape — this
  module produces one plausible request body to fuzz, not every
  schema-valid alternative.
* Postman Collection v2.1: ``request.body.raw`` is almost always a literal
  saved example already, so it's just ``json.loads()`` — no synthesis.
* Every path is rebased onto ``base_url`` (the scan's actual ``--target``),
  ignoring the spec's own ``servers``/``host`` — the same "stay scoped to
  the live target" rule every other recon source (nmap ports, subfinder
  hosts) already follows.
* A path template placeholder (OpenAPI ``{id}``, Postman ``:id`` or
  ``{{id}}``) is substituted with a numeric placeholder (``"1"``) — which
  ``core/json_fuzz.py``'s existing ``looks_like_object_reference`` already
  recognises as fuzzable, so REST path-segment fuzzing needs no changes
  either.
* ``--openapi``/``--postman`` accept a local path or an ``http(s)://`` URL
  interchangeably (the latter fetched directly, operator-supplied so no
  different trust level than ``--target`` itself) — no auto-discovery of a
  spec at a well-known path (``/openapi.json``, …) when neither flag is
  given at all; that remains a follow-up.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
import yaml

from .crawler import CapturedJsonRequest, CrawledEndpoint

logger = logging.getLogger(__name__)

#: Methods treated as carrying a JSON body worth fuzzing as such.
_BODY_METHODS = ("post", "put", "patch")
#: Methods recognised as operations at all (plus the body ones above).
_OPERATION_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

_PATH_PLACEHOLDER = "1"
_MAX_SCHEMA_DEPTH = 6
#: Timeout for fetching a spec from an http(s):// URL.
_FETCH_TIMEOUT = 15.0


def _load_spec_file(path: str) -> Optional[Dict[str, Any]]:
    """
    Load a spec as JSON or YAML (OpenAPI/Swagger allow either; Postman is
    JSON) — from a local file, or fetched directly when ``path`` is itself
    an ``http(s)://`` URL.
    """
    if path.startswith(("http://", "https://")):
        try:
            resp = requests.get(path, timeout=_FETCH_TIMEOUT)
            resp.raise_for_status()
        except requests.exceptions.RequestException as exc:
            logger.error("Could not fetch spec from %s: %s", path, exc)
            return None
        raw = resp.text
    else:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as exc:
            logger.error("Could not read spec file %s: %s", path, exc)
            return None

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        try:
            doc = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            logger.error("Could not parse %s as JSON or YAML: %s", path, exc)
            return None

    if not isinstance(doc, dict):
        logger.error("Spec file %s did not parse to an object", path)
        return None
    return doc


# ─────────────────────────────────────────────────────────────────────────────
# OpenAPI 3.x / Swagger 2.0
# ─────────────────────────────────────────────────────────────────────────────


def import_openapi_spec(path: str, base_url: str) -> List[CrawledEndpoint]:
    """
    Parse an OpenAPI 3.x or Swagger 2.0 spec (JSON or YAML) into synthetic
    :class:`~core.crawler.CrawledEndpoint`\\ s rebased onto ``base_url``.

    Never raises: a missing/unparseable file or a malformed spec degrades
    to an empty list with a logged error, the same "a scan must not fail
    just because an optional input source couldn't be read" rule
    ``core/dom_watcher.py`` follows for a missing Playwright install.
    """
    doc = _load_spec_file(path)
    if doc is None:
        return []

    is_swagger2 = "swagger" in doc
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        logger.error("OpenAPI/Swagger spec %s has no 'paths' object", path)
        return []

    endpoints: List[CrawledEndpoint] = []
    for path_template, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if method.lower() not in _OPERATION_METHODS or not isinstance(operation, dict):
                continue
            endpoints.append(
                _openapi_operation_endpoint(
                    base_url, path_template, method.lower(), operation, doc, is_swagger2
                )
            )

    logger.info(
        "spec_import: imported %d endpoint(s) from OpenAPI/Swagger spec %s", len(endpoints), path
    )
    return endpoints


def _openapi_operation_endpoint(
    base_url: str,
    path_template: str,
    method: str,
    operation: Dict[str, Any],
    doc: Dict[str, Any],
    is_swagger2: bool,
) -> CrawledEndpoint:
    parameters = operation.get("parameters", [])
    parameters = parameters if isinstance(parameters, list) else []

    path_types: Dict[str, str] = {}
    query_params: Dict[str, List[str]] = {}
    body_schema: Optional[Dict[str, Any]] = None

    for param in parameters:
        if not isinstance(param, dict):
            continue
        location = param.get("in")
        name = param.get("name")
        if not name:
            continue
        schema = param.get("schema", param)  # Swagger 2 flattens type onto the param itself.
        if location == "path":
            path_types[name] = schema.get("format") or schema.get("type", "string")
        elif location == "query":
            query_params[name] = [str(_synthesize_example(schema, doc))]
        elif location == "body" and is_swagger2:  # Swagger 2's only body-carrying shape.
            body_schema = param.get("schema")

    if not is_swagger2 and method in _BODY_METHODS:
        body_schema = (
            operation.get("requestBody", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema")
        )

    url = base_url.rstrip("/") + _substitute_path_template(path_template, path_types)

    if method in _BODY_METHODS and body_schema:
        body = _synthesize_example(body_schema, doc)
        return CrawledEndpoint(
            url=url,
            status_code=0,
            depth=0,
            json_requests=[CapturedJsonRequest(url=url, method=method.upper(), body=body)],
        )

    return CrawledEndpoint(url=url, status_code=0, depth=0, query_params=query_params)


def _substitute_path_template(path_template: str, path_types: Dict[str, str]) -> str:
    """Replace every ``{param}`` with a placeholder value fuzzable as a REST path segment."""

    def _replace(match: "re.Match[str]") -> str:
        name = match.group(1)
        if path_types.get(name) == "uuid":
            return "00000000-0000-0000-0000-000000000000"
        return _PATH_PLACEHOLDER

    return re.sub(r"\{([^}]+)\}", _replace, path_template)


def _resolve_ref(schema: Any, doc: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve a local ``$ref`` (``#/components/schemas/X`` or ``#/definitions/X``)."""
    if not isinstance(schema, dict):
        return {}
    ref = schema.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return schema
    node: Any = doc
    for part in ref[2:].split("/"):
        if not isinstance(node, dict):
            return {}
        node = node.get(part, {})
    return node if isinstance(node, dict) else {}


def _synthesize_example(schema: Any, doc: Dict[str, Any], _depth: int = 0) -> Any:
    """
    Produce a representative value for a JSON Schema fragment: the spec's
    own example/default/enum when present, else a type-appropriate
    placeholder. Depth-capped so a self-referential ``$ref`` degrades to
    ``None`` instead of recursing forever.

    ``allOf`` is merged — every subschema's synthesized value, plus the
    schema's own ``type``/``properties`` if it declares both at once (the
    common "base type + extension" composition pattern,
    e.g. ``{"allOf": [{"$ref": "#/Base"}], "properties": {...}}``) — into one
    representative object. ``oneOf``/``anyOf`` pick the first listed variant
    as the one representative shape: this module produces one plausible
    request body per operation to fuzz, not every schema-valid alternative.
    """
    if _depth > _MAX_SCHEMA_DEPTH or not isinstance(schema, dict):
        return None

    schema = _resolve_ref(schema, doc)
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]

    all_of = schema.get("allOf")
    if isinstance(all_of, list) and all_of:
        return _merge_all_of(schema, all_of, doc, _depth)

    for composition_key in ("oneOf", "anyOf"):
        variants = schema.get(composition_key)
        if isinstance(variants, list) and variants:
            return _synthesize_example(variants[0], doc, _depth + 1)

    return _synthesize_by_type(schema, doc, _depth)


def _merge_all_of(
    schema: Dict[str, Any], all_of: List[Any], doc: Dict[str, Any], _depth: int
) -> Any:
    """Shallow-merge every ``allOf`` subschema's synthesized object (later
    entries win on key conflicts). Falls back to the first subschema's own
    value when nothing here actually synthesizes to an object."""
    merged: Dict[str, Any] = {}
    saw_object = False
    for sub in all_of:
        value = _synthesize_example(sub, doc, _depth + 1)
        if isinstance(value, dict):
            merged.update(value)
            saw_object = True
    own = _synthesize_by_type(schema, doc, _depth)
    if isinstance(own, dict):
        merged.update(own)
        saw_object = True
    if saw_object:
        return merged
    return _synthesize_example(all_of[0], doc, _depth + 1)


def _synthesize_by_type(schema: Dict[str, Any], doc: Dict[str, Any], _depth: int) -> Any:
    """The type-appropriate placeholder/property-walk, once example/default/
    enum/allOf/oneOf/anyOf have already been handled by the caller."""
    schema_type = schema.get("type")
    if schema_type == "object" or "properties" in schema:
        properties = schema.get("properties", {})
        return {
            key: _synthesize_example(value, doc, _depth + 1)
            for key, value in properties.items()
            if isinstance(properties, dict)
        }
    if schema_type == "array":
        return [_synthesize_example(schema.get("items", {}), doc, _depth + 1)]
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1.0
    if schema_type == "boolean":
        return True
    if schema_type == "string":
        fmt = schema.get("format")
        if fmt == "uuid":
            return "00000000-0000-0000-0000-000000000000"
        if fmt == "date-time":
            return "2024-01-01T00:00:00Z"
        return "example"
    return "example"


# ─────────────────────────────────────────────────────────────────────────────
# Postman Collection v2.1
# ─────────────────────────────────────────────────────────────────────────────


def import_postman_collection(path: str, base_url: str) -> List[CrawledEndpoint]:
    """
    Parse a Postman Collection v2.1 JSON export into synthetic
    :class:`~core.crawler.CrawledEndpoint`\\ s rebased onto ``base_url``.

    Never raises — same degrade-to-empty-list rule as :func:`import_openapi_spec`.
    """
    doc = _load_spec_file(path)
    if doc is None:
        return []

    items = doc.get("item")
    if not isinstance(items, list):
        logger.error("Postman collection %s has no top-level 'item' array", path)
        return []

    endpoints: List[CrawledEndpoint] = []
    _walk_postman_items(items, base_url, endpoints)

    logger.info(
        "spec_import: imported %d endpoint(s) from Postman collection %s", len(endpoints), path
    )
    return endpoints


def _walk_postman_items(
    items: List[Any], base_url: str, endpoints: List[CrawledEndpoint]
) -> None:
    """Recurse into Postman folders (nested ``item`` arrays) to find leaf requests."""
    for item in items:
        if not isinstance(item, dict):
            continue
        nested = item.get("item")
        if isinstance(nested, list):
            _walk_postman_items(nested, base_url, endpoints)
            continue

        request = item.get("request")
        if not isinstance(request, dict):
            continue
        endpoint = _postman_request_endpoint(request, base_url)
        if endpoint is not None:
            endpoints.append(endpoint)


def _postman_request_endpoint(request: Dict[str, Any], base_url: str) -> Optional[CrawledEndpoint]:
    method = str(request.get("method", "GET")).upper()
    url = base_url.rstrip("/") + _postman_url_path(request.get("url"))

    if method.lower() in _BODY_METHODS:
        body_field = request.get("body")
        raw = body_field.get("raw") if isinstance(body_field, dict) else None
        if raw:
            try:
                body = json.loads(raw)
            except (TypeError, ValueError):
                body = None
            if body is not None:
                return CrawledEndpoint(
                    url=url,
                    status_code=0,
                    depth=0,
                    json_requests=[CapturedJsonRequest(url=url, method=method, body=body)],
                )

    return CrawledEndpoint(url=url, status_code=0, depth=0, query_params=_postman_query_params(request.get("url")))


def _postman_url_path(url_field: Any) -> str:
    """
    A Postman request's ``url`` is either a raw string or a structured
    object (``{raw, path: [...], query: [...], variable: [...]}}``). Both
    ``:id`` (path variable) and ``{{id}}`` (collection/environment
    variable) placeholder styles are replaced with a numeric placeholder —
    fuzzable the same way an OpenAPI ``{id}`` substitution is.
    """
    if isinstance(url_field, str):
        path = urlparse(url_field).path
    elif isinstance(url_field, dict):
        segments = url_field.get("path")
        if isinstance(segments, list) and segments:
            path = "/" + "/".join(str(segment) for segment in segments)
        else:
            path = urlparse(str(url_field.get("raw", ""))).path
    else:
        path = ""

    path = re.sub(r"\{\{[^}]+\}\}", _PATH_PLACEHOLDER, path)
    path = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", _PATH_PLACEHOLDER, path)
    return path or "/"


def _postman_query_params(url_field: Any) -> Dict[str, List[str]]:
    if not isinstance(url_field, dict):
        return {}
    query = url_field.get("query")
    if not isinstance(query, list):
        return {}
    params: Dict[str, List[str]] = {}
    for entry in query:
        if not isinstance(entry, dict) or entry.get("disabled"):
            continue
        key = entry.get("key")
        if not key:
            continue
        params[key] = [str(entry.get("value", "1"))]
    return params
