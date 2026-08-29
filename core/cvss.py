"""
VortexDAST – core/cvss.py
────────────────────────────────────────────────────────────────────────────
CVSS v3.1 Base Score Calculator.

Implements the official FIRST.org CVSS v3.1 specification formula exactly:
  https://www.first.org/cvss/v3.1/specification-document  (Section 7.1)

No external libraries required — pure Python arithmetic.

Usage
-----
::

    from core.cvss import calculate, build_vector, severity_label

    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    score  = calculate(vector)          # → 6.1
    label  = severity_label(score)      # → "MEDIUM"

    # Or build a vector string from individual metric values:
    vector = build_vector(AV="N", AC="L", PR="N", UI="R",
                          S="C", C="L", I="L", A="N")
    # → "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

CVSS v3.1 Metric Reference
---------------------------
  AV  Attack Vector      : N(etwork) A(djacent) L(ocal) P(hysical)
  AC  Attack Complexity  : L(ow) H(igh)
  PR  Privileges Required: N(one) L(ow) H(igh)
  UI  User Interaction   : N(one) R(equired)
  S   Scope              : U(nchanged) C(hanged)
  C   Confidentiality    : N(one) L(ow) H(igh)
  I   Integrity          : N(one) L(ow) H(igh)
  A   Availability       : N(one) L(ow) H(igh)
"""

from __future__ import annotations

import math
from typing import Dict

# ─────────────────────────────────────────────────────────────────────────────
# Numeric weights from CVSS v3.1 specification, Table 14
# ─────────────────────────────────────────────────────────────────────────────

_AV: Dict[str, float] = {
    "N": 0.85,   # Network
    "A": 0.62,   # Adjacent
    "L": 0.55,   # Local
    "P": 0.20,   # Physical
}

_AC: Dict[str, float] = {
    "L": 0.77,   # Low
    "H": 0.44,   # High
}

# Privileges Required weights differ depending on Scope (S:C vs S:U)
_PR_UNCHANGED: Dict[str, float] = {
    "N": 0.85,
    "L": 0.62,
    "H": 0.27,
}
_PR_CHANGED: Dict[str, float] = {
    "N": 0.85,
    "L": 0.68,
    "H": 0.50,
}

_UI: Dict[str, float] = {
    "N": 0.85,   # None
    "R": 0.62,   # Required
}

# Impact sub-score weights (C / I / A share the same table)
_IMPACT: Dict[str, float] = {
    "N": 0.00,   # None
    "L": 0.22,   # Low
    "H": 0.56,   # High
}

# Valid metric abbreviation values for input validation
_VALID_METRICS: Dict[str, set] = {
    "AV": set(_AV),
    "AC": set(_AC),
    "PR": set(_PR_UNCHANGED),
    "UI": set(_UI),
    "S":  {"U", "C"},
    "C":  set(_IMPACT),
    "I":  set(_IMPACT),
    "A":  set(_IMPACT),
}

# ─────────────────────────────────────────────────────────────────────────────
# Score → severity label mapping (CVSS v3.1 spec, Section 5)
# ─────────────────────────────────────────────────────────────────────────────

_SCORE_TO_SEVERITY = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (0.0, "INFORMATIONAL"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def calculate(vector: str) -> float:
    """
    Compute the CVSS v3.1 base score for the given vector string.

    Parameters
    ----------
    vector : str
        A fully-qualified CVSS v3.1 vector string, e.g.
        ``"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"``.
        The ``CVSS:3.1/`` prefix is optional.

    Returns
    -------
    float
        Numeric base score in the range 0.0 – 10.0, rounded up to
        one decimal place as required by the CVSS specification
        (ceiling rounding, not standard rounding).

    Raises
    ------
    ValueError
        If the vector string is malformed or contains invalid metric values.

    Examples
    --------
    >>> calculate("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    6.1
    >>> calculate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    9.8
    """
    metrics = _parse_vector(vector)
    return _compute(metrics)


def build_vector(
    *,
    AV: str,
    AC: str,
    PR: str,
    UI: str,
    S: str,
    C: str,
    I: str,
    A: str,
) -> str:
    """
    Construct a canonical CVSS v3.1 vector string from individual metric values.

    Returns
    -------
    str
        A fully-qualified CVSS v3.1 vector string.

    Example
    -------
    >>> build_vector(AV="N", AC="L", PR="N", UI="R",
    ...              S="C", C="L", I="L", A="N")
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'
    """
    metrics = {"AV": AV, "AC": AC, "PR": PR, "UI": UI,
               "S": S, "C": C, "I": I, "A": A}
    _validate_metrics(metrics)
    return (
        f"CVSS:3.1/AV:{AV}/AC:{AC}/PR:{PR}/UI:{UI}"
        f"/S:{S}/C:{C}/I:{I}/A:{A}"
    )


def severity_label(score: float) -> str:
    """
    Map a numeric CVSS base score to its severity label string.

    Returns one of: ``"CRITICAL"``, ``"HIGH"``, ``"MEDIUM"``, ``"LOW"``,
    ``"INFORMATIONAL"``.

    Example
    -------
    >>> severity_label(9.8)
    'CRITICAL'
    >>> severity_label(6.1)
    'MEDIUM'
    """
    for threshold, label in _SCORE_TO_SEVERITY:
        if score >= threshold:
            return label
    return "INFORMATIONAL"


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────


def _parse_vector(vector: str) -> Dict[str, str]:
    """Parse a CVSS v3.1 vector string into a dict of metric → value."""
    cleaned = vector.strip()
    for prefix in ("CVSS:3.1/", "CVSS:3.0/"):
        if cleaned.upper().startswith(prefix):
            cleaned = cleaned[len(prefix):]
            break

    parts = cleaned.split("/")
    if len(parts) != 8:
        raise ValueError(
            f"CVSS v3.1 vector must have exactly 8 metric components, "
            f"got {len(parts)}: '{vector}'"
        )

    metrics: Dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            raise ValueError(f"Malformed CVSS metric component: '{part}'")
        key, val = part.split(":", 1)
        metrics[key.upper()] = val.upper()

    _validate_metrics(metrics)
    return metrics


def _validate_metrics(metrics: Dict[str, str]) -> None:
    """Raise ``ValueError`` if any metric key or value is unrecognised."""
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = required - metrics.keys()
    if missing:
        raise ValueError(f"CVSS vector is missing metrics: {missing}")

    for metric, value in metrics.items():
        if metric in _VALID_METRICS and value not in _VALID_METRICS[metric]:
            raise ValueError(
                f"Invalid value '{value}' for CVSS metric '{metric}'. "
                f"Valid values: {sorted(_VALID_METRICS[metric])}"
            )


def _roundup(value: float) -> float:
    """
    CVSS v3.1 ceiling rounding to one decimal place.

    The spec requires ceiling rounding (not half-even).
    e.g. 4.02 → 4.1, not 4.0.
    """
    return math.ceil(value * 10) / 10


def _compute(m: Dict[str, str]) -> float:
    """Execute the CVSS v3.1 base score formula against parsed metric dict."""
    scope_changed = m["S"] == "C"

    av = _AV[m["AV"]]
    ac = _AC[m["AC"]]
    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
    ui = _UI[m["UI"]]
    c  = _IMPACT[m["C"]]
    i  = _IMPACT[m["I"]]
    a  = _IMPACT[m["A"]]

    # Exploitability sub-score
    ess = 8.22 * av * ac * pr * ui

    # Impact sub-score
    iss_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope_changed:
        iss = 7.52 * (iss_base - 0.029) - 3.25 * ((iss_base - 0.02) ** 15)
    else:
        iss = 6.42 * iss_base

    # Zero impact → score is 0
    if iss <= 0:
        return 0.0

    # Base score
    if scope_changed:
        raw_score = min(1.08 * (iss + ess), 10.0)
    else:
        raw_score = min(iss + ess, 10.0)

    return _roundup(raw_score)
