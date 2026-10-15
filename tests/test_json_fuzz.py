"""
VortexDAST – tests/test_json_fuzz.py
────────────────────────────────────────────────────────────────────────────
Unit tests for core/json_fuzz.py — the shared JSON-leaf / REST-path-segment
fuzzing primitives Phase D's API-testing modules build on.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crawler import CapturedJsonRequest
from core.json_fuzz import (
    find_fuzzable_path_segments,
    fuzz_targets_for,
    looks_like_object_reference,
    render_path,
    set_leaf,
    substitute_path_segment,
    walk_json_leaves,
)


class TestWalkJsonLeaves:
    def test_nested_object_and_array(self) -> None:
        body = {
            "user": {"name": "bob", "address": {"zip": "12345"}},
            "items": [{"qty": 3}, {"qty": 7}],
        }
        leaves = walk_json_leaves(body)
        paths = {render_path(leaf.path): leaf.value for leaf in leaves}
        assert paths == {
            "user.name": "bob",
            "user.address.zip": "12345",
            "items[0].qty": 3,
            "items[1].qty": 7,
        }

    def test_scalar_body_is_its_own_leaf(self) -> None:
        leaves = walk_json_leaves("just a string")
        assert len(leaves) == 1
        assert leaves[0].path == ()
        assert render_path(leaves[0].path) == "$"

    def test_max_leaves_caps_a_large_body(self) -> None:
        body = {f"field{i}": i for i in range(100)}
        leaves = walk_json_leaves(body, max_leaves=5)
        assert len(leaves) == 5

    def test_none_and_bool_leaves_included(self) -> None:
        leaves = walk_json_leaves({"active": True, "note": None})
        values = {render_path(leaf.path): leaf.value for leaf in leaves}
        assert values == {"active": True, "note": None}


class TestSetLeaf:
    def test_replaces_nested_leaf_without_mutating_original(self) -> None:
        body = {"user": {"address": {"zip": "12345"}}}
        updated = set_leaf(body, ("user", "address", "zip"), "99999")
        assert updated["user"]["address"]["zip"] == "99999"
        assert body["user"]["address"]["zip"] == "12345"

    def test_replaces_array_element(self) -> None:
        body = {"items": [{"qty": 3}, {"qty": 7}]}
        updated = set_leaf(body, ("items", 1, "qty"), 999)
        assert updated["items"][1]["qty"] == 999
        assert updated["items"][0]["qty"] == 3

    def test_root_level_scalar_replacement(self) -> None:
        assert set_leaf("original", (), "replaced") == "replaced"


class TestPathSegments:
    def test_finds_numeric_and_uuid_segments(self) -> None:
        url = "http://x/api/users/42/orders/550e8400-e29b-41d4-a716-446655440000"
        found = find_fuzzable_path_segments(url)
        assert found == [(3, "42"), (5, "550e8400-e29b-41d4-a716-446655440000")]

    def test_ignores_non_id_segments(self) -> None:
        found = find_fuzzable_path_segments("http://x/api/users/search")
        assert found == []

    def test_substitute_path_segment(self) -> None:
        url = "http://x/api/users/42/profile"
        new_url = substitute_path_segment(url, 3, "99")
        assert new_url == "http://x/api/users/99/profile"

    def test_looks_like_object_reference(self) -> None:
        assert looks_like_object_reference("42") is True
        assert looks_like_object_reference("550e8400-e29b-41d4-a716-446655440000") is True
        assert looks_like_object_reference("search") is False
        assert looks_like_object_reference("") is False


class TestFuzzTargetsFor:
    def test_body_leaves_and_path_segments_both_produced(self) -> None:
        captured = CapturedJsonRequest(
            url="http://x/api/widgets/7", method="POST", body={"qty": 3}
        )
        targets = fuzz_targets_for(captured)
        kinds = {t.kind for t in targets}
        assert kinds == {"body", "path"}

        body_target = next(t for t in targets if t.kind == "body")
        assert body_target.label == "body:qty"
        url, body = body_target.build("INJECT")
        assert url == captured.url
        assert body == {"qty": "3INJECT"}

        path_target = next(t for t in targets if t.kind == "path")
        assert path_target.label == "path:segment[3]=7"
        url, body = path_target.build("INJECT")
        assert url == "http://x/api/widgets/7INJECT"
        assert body == {"qty": 3}

    def test_body_leaf_replace_does_not_mutate_original_body(self) -> None:
        captured = CapturedJsonRequest(url="http://x/api/widgets/7", method="POST", body={"qty": 3})
        target = next(t for t in fuzz_targets_for(captured) if t.kind == "body")
        assert target.replace is not None
        _, replaced = target.replace({"$ne": "x"})
        assert replaced == {"qty": {"$ne": "x"}}
        assert captured.body == {"qty": 3}

    def test_path_target_replace_substitutes_whole_segment(self) -> None:
        captured = CapturedJsonRequest(url="http://x/api/widgets/7", method="POST", body={"qty": 3})
        path_target = next(t for t in fuzz_targets_for(captured) if t.kind == "path")
        assert path_target.replace is not None
        url, body = path_target.replace("INJECT")
        assert url == "http://x/api/widgets/INJECT"
        assert body == {"qty": 3}

    def test_path_target_replace_coerces_non_string_value(self) -> None:
        captured = CapturedJsonRequest(url="http://x/api/widgets/7", method="POST", body={"qty": 3})
        path_target = next(t for t in fuzz_targets_for(captured) if t.kind == "path")
        url, _ = path_target.replace(99)
        assert url == "http://x/api/widgets/99"

    def test_no_fuzzable_path_segments_yields_body_only(self) -> None:
        captured = CapturedJsonRequest(url="http://x/api/widgets", method="POST", body={"qty": 3})
        targets = fuzz_targets_for(captured)
        assert all(t.kind == "body" for t in targets)
