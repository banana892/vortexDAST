"""
VortexDAST – tests/test_phase3_config.py
────────────────────────────────────────────────────────────────────────────
Tests for Phase 3 configuration management (core.profiles):
  • Scan profiles (aggressive / balanced / quiet)
  • VORTEX_* environment-variable overrides + precedence
  • Config validation (fail-fast on bad types)
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.profiles import (
    PROFILE_NAMES,
    SCAN_PROFILES,
    ConfigError,
    apply_env_overrides,
    apply_profile,
    validate_config,
)


class TestProfiles:
    def test_profile_names(self) -> None:
        assert set(PROFILE_NAMES) == {"aggressive", "balanced", "quiet"}

    def test_apply_profile_sets_values(self) -> None:
        cfg = {"crawler": {}, "requester": {}}
        apply_profile(cfg, "aggressive")
        assert cfg["crawler"]["max_depth"] == SCAN_PROFILES["aggressive"]["max_depth"]
        assert cfg["requester"]["rate_limit_rps"] == 50.0
        assert cfg["requester"]["concurrency"] == 30

    def test_apply_profile_quiet(self) -> None:
        cfg = {}
        apply_profile(cfg, "quiet")
        assert cfg["crawler"]["max_depth"] == 2
        assert cfg["requester"]["concurrency"] == 5

    def test_unknown_profile_raises(self) -> None:
        with pytest.raises(ConfigError):
            apply_profile({}, "turbo")


class TestEnvOverrides:
    def test_env_overrides_applied(self) -> None:
        cfg = {"requester": {"timeout": 10}}
        env = {"VORTEX_TIMEOUT": "30", "VORTEX_RATE_LIMIT": "2.5", "VORTEX_PROXY": "http://p:8080"}
        apply_env_overrides(cfg, env)
        assert cfg["requester"]["timeout"] == 30
        assert cfg["requester"]["rate_limit_rps"] == 2.5
        assert cfg["requester"]["proxy"] == "http://p:8080"

    def test_env_overrides_profile(self) -> None:
        cfg = {}
        apply_profile(cfg, "quiet")  # max_depth 2
        apply_env_overrides(cfg, {"VORTEX_MAX_DEPTH": "7"})
        assert cfg["crawler"]["max_depth"] == 7  # env wins over profile

    def test_invalid_env_numeric_raises(self) -> None:
        with pytest.raises(ConfigError):
            apply_env_overrides({}, {"VORTEX_TIMEOUT": "notanumber"})

    def test_no_env_is_noop(self) -> None:
        cfg = {"requester": {"timeout": 10}}
        apply_env_overrides(cfg, {})
        assert cfg == {"requester": {"timeout": 10}}


class TestValidation:
    def test_valid_config_passes(self) -> None:
        cfg = {
            "requester": {"timeout": 10, "rate_limit_rps": 5, "verify_ssl": True, "proxy": None},
            "crawler": {"max_depth": 3},
            "scope": {"excluded_paths": ["/logout"]},
        }
        validate_config(cfg)  # no raise

    def test_negative_timeout_rejected(self) -> None:
        with pytest.raises(ConfigError):
            validate_config({"requester": {"timeout": -1}})

    def test_bool_timeout_rejected(self) -> None:
        # bool must not pass as int
        with pytest.raises(ConfigError):
            validate_config({"requester": {"timeout": True}})

    def test_non_numeric_rate_limit_rejected(self) -> None:
        with pytest.raises(ConfigError):
            validate_config({"requester": {"rate_limit_rps": "fast"}})

    def test_bad_verify_ssl_rejected(self) -> None:
        with pytest.raises(ConfigError):
            validate_config({"requester": {"verify_ssl": "yes"}})

    def test_scope_must_be_list(self) -> None:
        with pytest.raises(ConfigError):
            validate_config({"scope": {"excluded_paths": "/logout"}})

    def test_negative_max_depth_rejected(self) -> None:
        with pytest.raises(ConfigError):
            validate_config({"crawler": {"max_depth": -2}})
