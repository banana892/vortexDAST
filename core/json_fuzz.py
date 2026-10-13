"""
VortexDAST – core/json_fuzz.py
────────────────────────────────────────────────────────────────────────────
Shared JSON-body and REST-path-segment fuzzing primitives.

Why this exists
----------------
``sqli_check``, ``nosql_check`` and ``xss_check`` already fuzz GET query
parameters and POST form fields. They want to run those exact same probes
against two more parts of a captured JSON API request
(:class:`~core.crawler.CapturedJsonRequest`, discovered by
``core.dom_watcher`` during a dynamic crawl):

  * every scalar leaf inside its (possibly nested) JSON body, and
  * any URL path segment that looks like a REST object reference
    (``/users/{id}``).

This module provides the walking/rebuilding primitives so each module keeps
its own detection logic (error patterns, boolean-blind diffing, reflection
checks, ...) and only needs to plug in a new *target* to fuzz, not a new
fuzzing engine.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Tuple, Union
from urllib.parse import urlparse

from .crawler import CapturedJsonRequest

#: Hard cap on JSON leaves walked per captured request — bounds request
#: volume against a large/pathological body (e.g. an array of hundreds of
#: records), the same volume-control concern as every other adapter/module's
#: own per-run cap.
DEFAULT_MAX_LEAVES = 15

_JsonPathSegment = Union[str, int]
_JsonPath = Tuple[_JsonPathSegment, ...]

#: A path segment made entirely of digits, or shaped like a UUID, is treated
#: as a REST object reference worth fuzzing. Mirrors the numeric-ID
#: heuristic ``modules/access_control_check.py`` already uses for query
#: parameters (``_is_object_ref``) — a URL path segment carries no parameter
#: name to check against a curated list, so a UUID shape is added as the
#: other identifier shape REST APIs commonly use.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


@dataclass(frozen=True)
class JsonLeaf:
    """One scalar value inside a (possibly nested) JSON body."""

    path: _JsonPath
    value: Any


def walk_json_leaves(obj: Any, max_leaves: int = DEFAULT_MAX_LEAVES) -> List[JsonLeaf]:
    """
    Depth-first walk of ``obj`` (a parsed JSON body) yielding every scalar
    leaf (``str``/``int``/``float``/``bool``/``None``) with its path, e.g.
    ``("user", "address", "zip")`` or ``("items", 0, "qty")``. Stops at
    ``max_leaves`` so a pathologically large body can't turn one captured
    request into hundreds of fuzz requests.
    """
    leaves: List[JsonLeaf] = []

    def _walk(node: Any, path: _JsonPath) -> None:
        if len(leaves) >= max_leaves:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if len(leaves) >= max_leaves:
                    return
                _walk(value, path + (key,))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                if len(leaves) >= max_leaves:
                    return
                _walk(value, path + (index,))
        else:
            leaves.append(JsonLeaf(path=path, value=node))

    _walk(obj, ())
    return leaves


def render_path(path: _JsonPath) -> str:
    """Render a leaf path as a human-readable pointer, e.g. ``items[0].qty``."""
    if not path:
        return "$"
    parts: List[str] = []
    for segment in path:
        if isinstance(segment, int):
            parts.append(f"[{segment}]")
        elif parts:
            parts.append(f".{segment}")
        else:
            parts.append(str(segment))
    return "".join(parts)


def set_leaf(obj: Any, path: _JsonPath, new_value: Any) -> Any:
    """Return a deep copy of ``obj`` with the leaf at ``path`` replaced."""
    result = copy.deepcopy(obj)
    if not path:
        return new_value
    node = result
    for segment in path[:-1]:
        node = node[segment]
    node[path[-1]] = new_value
    return result


def looks_like_object_reference(segment: str) -> bool:
    """A path segment shaped like a numeric ID or a UUID — worth fuzzing."""
    if not segment:
        return False
    return segment.isdigit() or bool(_UUID_RE.match(segment))


def find_fuzzable_path_segments(url: str) -> List[Tuple[int, str]]:
    """
    Return ``(index, segment)`` for every URL path segment that looks like a
    REST object reference, e.g. ``/users/42`` → ``[(2, "42")]``.
    """
    segments = urlparse(url).path.split("/")
    return [
        (index, segment)
        for index, segment in enumerate(segments)
        if looks_like_object_reference(segment)
    ]


def substitute_path_segment(url: str, index: int, new_segment: str) -> str:
    """Rebuild ``url`` with the path segment at ``index`` replaced."""
    parsed = urlparse(url)
    segments = parsed.path.split("/")
    segments[index] = new_segment
    return parsed._replace(path="/".join(segments)).geturl()


@dataclass
class FuzzTarget:
    """
    One mutable position inside a captured JSON request — either a JSON
    body leaf or a REST-style path segment — exposed uniformly so a module
    can run its existing probes against it without caring which it is.
    """

    #: Reported as ``Finding.parameter``, e.g. ``body:user.address.zip`` or
    #: ``path:segment[2]=42``.
    label: str
    #: Original value as a string (probes that append to it need this).
    original: str
    #: ``"body"`` or ``"path"`` — callers that only make sense against a
    #: body leaf (operator-injection, boolean/time-based blind) check this.
    kind: str
    #: probe_value -> (url, json_body), appending probe_value to the
    #: original value. Works for both kinds.
    build: Callable[[str], Tuple[str, Any]]
    #: new_value -> (url, json_body), replacing the leaf outright. Only set
    #: for ``"body"`` targets — a URL path segment can't hold a non-string
    #: JSON value.
    replace: Optional[Callable[[Any], Tuple[str, Any]]] = None


def fuzz_targets_for(
    captured: CapturedJsonRequest, max_leaves: int = DEFAULT_MAX_LEAVES
) -> List[FuzzTarget]:
    """Every body leaf and fuzzable path segment of ``captured``, as uniform targets."""
    targets: List[FuzzTarget] = []

    for leaf in walk_json_leaves(captured.body, max_leaves=max_leaves):
        original = "" if leaf.value is None else str(leaf.value)
        label = f"body:{render_path(leaf.path)}"

        def _build(probe_value: str, _path=leaf.path, _orig=original) -> Tuple[str, Any]:
            return captured.url, set_leaf(captured.body, _path, _orig + probe_value)

        def _replace(new_value: Any, _path=leaf.path) -> Tuple[str, Any]:
            return captured.url, set_leaf(captured.body, _path, new_value)

        targets.append(
            FuzzTarget(label=label, original=original, kind="body", build=_build, replace=_replace)
        )

    for index, segment in find_fuzzable_path_segments(captured.url):
        label = f"path:segment[{index}]={segment}"

        def _build_path(probe_value: str, _index=index, _segment=segment) -> Tuple[str, Any]:
            return substitute_path_segment(captured.url, _index, _segment + probe_value), captured.body

        targets.append(FuzzTarget(label=label, original=segment, kind="path", build=_build_path))

    return targets
