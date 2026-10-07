"""
VortexDAST – core/endpoint_group.py
────────────────────────────────────────────────────────────────────────────
Endpoint grouping for batch analysis.

Large crawls frequently surface many endpoints that are structurally the same
attack surface — e.g. ``/item?id=1``, ``/item?id=2``, … ``/item?id=500`` — which
differ only in parameter *values*. Fuzzing every one of them repeats identical
probes and dominates scan time.

This module collapses endpoints that share a structural *signature* (host +
path + the set of query-parameter names + a form signature) down to a single
representative, so each distinct attack surface is probed once. It is a pure
function with no I/O, which keeps it trivially testable and side-effect free.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, List, Tuple
from urllib.parse import urlparse

from core.crawler import CrawledEndpoint

logger = logging.getLogger(__name__)


def endpoint_signature(ep: CrawledEndpoint) -> Tuple[Any, ...]:
    """
    Structural signature of an endpoint, independent of parameter *values*.

    Two endpoints with the same signature expose the same attack surface and
    only one needs fuzzing.
    """
    parsed = urlparse(ep.url)
    origin_path = (parsed.scheme, parsed.netloc, parsed.path or "/")
    param_names = tuple(sorted(ep.query_params.keys()))

    form_sigs = tuple(sorted(
        (
            urlparse(getattr(f, "action_url", "")).path,
            getattr(f, "method", "GET"),
            tuple(sorted(getattr(field, "name", "") for field in getattr(f, "fields", []))),
        )
        for f in ep.forms
    ))
    return (origin_path, param_names, form_sigs)


@dataclass
class GroupingResult:
    """Outcome of :func:`group_endpoints`."""

    representatives: List[CrawledEndpoint]
    """One endpoint per distinct structural signature."""

    collapsed: int
    """How many endpoints were removed as structural duplicates."""

    groups: int
    """Number of distinct signatures (== len(representatives))."""


def group_endpoints(endpoints: List[CrawledEndpoint]) -> GroupingResult:
    """
    Collapse structurally-equivalent endpoints to one representative each.

    The first endpoint seen for a given signature is kept (preserving order).
    """
    seen: dict = {}
    representatives: List[CrawledEndpoint] = []

    for ep in endpoints:
        sig = endpoint_signature(ep)
        if sig in seen:
            continue
        seen[sig] = True
        representatives.append(ep)

    collapsed = len(endpoints) - len(representatives)
    if collapsed > 0:
        logger.info(
            "Endpoint grouping: %d endpoints → %d distinct attack surfaces "
            "(%d collapsed)",
            len(endpoints), len(representatives), collapsed,
        )
    return GroupingResult(
        representatives=representatives,
        collapsed=collapsed,
        groups=len(representatives),
    )
