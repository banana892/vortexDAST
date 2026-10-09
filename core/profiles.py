"""
VortexDAST – core/profiles.py
────────────────────────────────────────────────────────────────────────────
Configuration management: pre-built scan profiles, environment-variable
overrides, and config validation.

Setting precedence (highest wins):

    explicit CLI flag  >  VORTEX_* env var  >  --profile  >  config.yaml  >  built-in default

Profiles and env overrides are applied by mutating the loaded config dict in
place; the scanner's existing ``args.X if args.X is not None else config[...]``
resolution then lets explicit CLI flags win over everything.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, Tuple

from core.theme import THEME_NAMES

logger = logging.getLogger(__name__)


class ConfigError(ValueError):
    """Raised when configuration (file, profile, or env var) is invalid."""


# ─────────────────────────────────────────────────────────────────────────────
# Scan profiles
# ─────────────────────────────────────────────────────────────────────────────

SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    "aggressive": {"max_depth": 5, "concurrency": 30, "rate_limit_rps": 50.0},
    "balanced":   {"max_depth": 3, "concurrency": 10, "rate_limit_rps": 5.0},
    "quiet":      {"max_depth": 2, "concurrency": 5,  "rate_limit_rps": 1.0},
}

PROFILE_NAMES = tuple(SCAN_PROFILES)


def apply_profile(config: Dict[str, Any], profile: str) -> Dict[str, Any]:
    """Merge a named profile into ``config`` (over config.yaml, under env/CLI)."""
    if profile not in SCAN_PROFILES:
        raise ConfigError(
            f"unknown profile {profile!r}; choose from {', '.join(PROFILE_NAMES)}"
        )
    settings = SCAN_PROFILES[profile]
    crawler = config.setdefault("crawler", {})
    requester = config.setdefault("requester", {})

    crawler["max_depth"] = settings["max_depth"]
    requester["rate_limit_rps"] = settings["rate_limit_rps"]
    requester["concurrency"] = settings["concurrency"]
    logger.info("Applied scan profile %r: %s", profile, settings)
    return config


# ─────────────────────────────────────────────────────────────────────────────
# Environment-variable overrides
# ─────────────────────────────────────────────────────────────────────────────

def _as_bool(raw: str) -> bool:
    """Parse a boolean env var; accepts 1/true/yes/on and 0/false/no/off."""
    value = str(raw).strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off", ""):
        return False
    raise ValueError(f"{raw!r} is not a boolean")


# env var → (config section, key, caster)
_ENV_MAP: Dict[str, Tuple[str, str, Callable[[str], Any]]] = {
    "VORTEX_TIMEOUT":    ("requester", "timeout", int),
    "VORTEX_RATE_LIMIT": ("requester", "rate_limit_rps", float),
    "VORTEX_MAX_DEPTH":  ("crawler", "max_depth", int),
    "VORTEX_THREADS":    ("requester", "concurrency", int),
    "VORTEX_CONCURRENCY": ("requester", "concurrency", int),
    "VORTEX_PROXY":      ("requester", "proxy", str),
    "VORTEX_USER_AGENT": ("requester", "user_agent", str),
    "VORTEX_THEME":      ("ui", "theme", str),
    "VORTEX_NO_COLOR":   ("ui", "no_color", _as_bool),
}


def apply_env_overrides(
    config: Dict[str, Any], environ: Dict[str, str] | None = None
) -> Dict[str, Any]:
    """Overlay ``VORTEX_*`` environment variables onto ``config`` (over profile)."""
    env = environ if environ is not None else os.environ
    for var, (section, key, caster) in _ENV_MAP.items():
        if var not in env:
            continue
        raw = env[var]
        try:
            value = caster(raw)
        except (TypeError, ValueError):
            kind = getattr(caster, "__name__", str(caster)).lstrip("_")
            raise ConfigError(f"{var}={raw!r} is not a valid {kind}")
        config.setdefault(section, {})[key] = value
        logger.info("Env override %s → %s.%s = %r", var, section, key, value)
    return config


# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise ConfigError(message)


def validate_config(config: Dict[str, Any]) -> None:
    """
    Validate the merged configuration, raising :class:`ConfigError` on the first
    problem so the scan fails fast with a clear message instead of mid-run.
    """
    _require(isinstance(config, dict), "config root must be a mapping")

    req = config.get("requester", {})
    _require(isinstance(req, dict), "'requester' section must be a mapping")
    if "timeout" in req:
        _require(_is_int(req["timeout"]) and req["timeout"] > 0,
                 "requester.timeout must be a positive integer")
    if "rate_limit_rps" in req:
        _require(_is_number(req["rate_limit_rps"]) and req["rate_limit_rps"] >= 0,
                 "requester.rate_limit_rps must be a non-negative number")
    if "max_retries" in req:
        _require(_is_int(req["max_retries"]) and req["max_retries"] >= 0,
                 "requester.max_retries must be a non-negative integer")
    if "concurrency" in req:
        _require(_is_int(req["concurrency"]) and req["concurrency"] > 0,
                 "requester.concurrency must be a positive integer")
    if "verify_ssl" in req:
        _require(isinstance(req["verify_ssl"], bool),
                 "requester.verify_ssl must be true or false")
    if req.get("proxy") is not None:
        _require(isinstance(req["proxy"], str), "requester.proxy must be a string or null")
    if "user_agent" in req:
        _require(isinstance(req["user_agent"], str), "requester.user_agent must be a string")

    crawler = config.get("crawler", {})
    _require(isinstance(crawler, dict), "'crawler' section must be a mapping")
    if "max_depth" in crawler:
        _require(_is_int(crawler["max_depth"]) and crawler["max_depth"] >= 0,
                 "crawler.max_depth must be a non-negative integer")

    ui = config.get("ui", {})
    _require(isinstance(ui, dict), "'ui' section must be a mapping")
    if ui.get("theme") is not None:
        _require(isinstance(ui["theme"], str), "ui.theme must be a string")
        _require(
            ui["theme"].strip().lower() in THEME_NAMES,
            f"ui.theme must be one of: {', '.join(THEME_NAMES)}",
        )
    if "no_color" in ui:
        _require(isinstance(ui["no_color"], bool), "ui.no_color must be true or false")

    scope = config.get("scope", {})
    _require(isinstance(scope, dict), "'scope' section must be a mapping")
    for list_key in ("allowed_domains", "allowed_paths", "excluded_paths"):
        if list_key in scope:
            _require(isinstance(scope[list_key], list),
                     f"scope.{list_key} must be a list")


def _is_int(value: Any) -> bool:
    # bool is a subclass of int — exclude it so True/False aren't valid numbers.
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool))
