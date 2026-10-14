"""
VortexDAST – tests/test_spec_import.py
────────────────────────────────────────────────────────────────────────────
Unit tests for core/spec_import.py — OpenAPI 3.x / Swagger 2.0 / Postman
Collection v2.1 import (Phase 3 of IMPROVEMENTS.md's "API testing" item).
"""

from __future__ import annotations

import json
import os
import sys

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.spec_import import import_openapi_spec, import_postman_collection

_BASE_URL = "https://target.example"


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(content)
    return str(path)


# ─────────────────────────────────────────────────────────────────────────────
# OpenAPI 3.x
# ─────────────────────────────────────────────────────────────────────────────


class TestOpenApi3:
    _SPEC = {
        "openapi": "3.0.0",
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "schema": {"type": "integer"}}
                    ]
                },
                "put": {
                    "parameters": [
                        {"name": "id", "in": "path", "schema": {"type": "integer"}}
                    ],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string", "example": "bob"},
                                        "address": {
                                            "type": "object",
                                            "properties": {"zip": {"type": "string"}},
                                        },
                                        "tags": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                        },
                                        "active": {"type": "boolean"},
                                    },
                                }
                            }
                        }
                    },
                },
            },
            "/search": {
                "get": {
                    "parameters": [
                        {
                            "name": "q",
                            "in": "query",
                            "schema": {"type": "string", "default": "hello"},
                        }
                    ]
                }
            },
        },
    }

    def test_path_param_becomes_fuzzable_placeholder(self, tmp_path) -> None:
        path = _write(tmp_path, "spec.json", json.dumps(self._SPEC))
        endpoints = import_openapi_spec(path, _BASE_URL)
        urls = {ep.url for ep in endpoints}
        assert f"{_BASE_URL}/users/1" in urls

    def test_request_body_synthesized_from_schema(self, tmp_path) -> None:
        path = _write(tmp_path, "spec.json", json.dumps(self._SPEC))
        endpoints = import_openapi_spec(path, _BASE_URL)
        put_endpoint = next(
            ep for ep in endpoints if ep.json_requests and ep.json_requests[0].method == "PUT"
        )
        body = put_endpoint.json_requests[0].body
        assert body["name"] == "bob"  # explicit example wins
        assert body["address"]["zip"] == "example"  # synthesized string
        assert body["tags"] == ["example"]  # synthesized array
        assert body["active"] is True  # synthesized boolean

    def test_query_param_default_used(self, tmp_path) -> None:
        path = _write(tmp_path, "spec.json", json.dumps(self._SPEC))
        endpoints = import_openapi_spec(path, _BASE_URL)
        search_endpoint = next(ep for ep in endpoints if ep.url.endswith("/search"))
        assert search_endpoint.query_params == {"q": ["hello"]}

    def test_get_operation_has_no_json_requests(self, tmp_path) -> None:
        path = _write(tmp_path, "spec.json", json.dumps(self._SPEC))
        endpoints = import_openapi_spec(path, _BASE_URL)
        get_users = next(
            ep for ep in endpoints if ep.url.endswith("/users/1") and not ep.json_requests
        )
        assert get_users.json_requests == []

    def test_yaml_spec_parses(self, tmp_path) -> None:
        path = _write(tmp_path, "spec.yaml", yaml.safe_dump(self._SPEC))
        endpoints = import_openapi_spec(path, _BASE_URL)
        assert len(endpoints) == 3

    def test_ref_schema_resolved(self, tmp_path) -> None:
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/widgets": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Widget"}
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Widget": {
                        "type": "object",
                        "properties": {"qty": {"type": "integer"}},
                    }
                }
            },
        }
        path = _write(tmp_path, "spec.json", json.dumps(spec))
        endpoints = import_openapi_spec(path, _BASE_URL)
        assert endpoints[0].json_requests[0].body == {"qty": 1}

    def test_self_referential_ref_does_not_hang(self, tmp_path) -> None:
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/nodes": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Node"}
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Node": {
                        "type": "object",
                        "properties": {"child": {"$ref": "#/components/schemas/Node"}},
                    }
                }
            },
        }
        path = _write(tmp_path, "spec.json", json.dumps(spec))
        endpoints = import_openapi_spec(path, _BASE_URL)
        assert endpoints  # terminates instead of recursing forever

    def test_missing_file_returns_empty(self) -> None:
        assert import_openapi_spec("/nonexistent/spec.json", _BASE_URL) == []

    def test_invalid_content_returns_empty(self, tmp_path) -> None:
        path = _write(tmp_path, "spec.json", "not json or yaml: [unterminated")
        assert import_openapi_spec(path, _BASE_URL) == []

    def test_no_paths_key_returns_empty(self, tmp_path) -> None:
        path = _write(tmp_path, "spec.json", json.dumps({"openapi": "3.0.0"}))
        assert import_openapi_spec(path, _BASE_URL) == []


# ─────────────────────────────────────────────────────────────────────────────
# Schema composition: allOf / oneOf / anyOf
# ─────────────────────────────────────────────────────────────────────────────


def _body_request_spec(schema: dict) -> dict:
    return {
        "openapi": "3.0.0",
        "paths": {
            "/widgets": {
                "post": {
                    "requestBody": {
                        "content": {"application/json": {"schema": schema}}
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Base": {
                    "type": "object",
                    "properties": {"name": {"type": "string", "example": "gadget"}},
                }
            }
        },
    }


class TestSchemaComposition:
    def test_all_of_merges_subschemas(self, tmp_path) -> None:
        schema = {
            "allOf": [
                {"$ref": "#/components/schemas/Base"},
                {"type": "object", "properties": {"qty": {"type": "integer"}}},
            ]
        }
        path = _write(tmp_path, "spec.json", json.dumps(_body_request_spec(schema)))
        endpoints = import_openapi_spec(path, _BASE_URL)
        assert endpoints[0].json_requests[0].body == {"name": "gadget", "qty": 1}

    def test_all_of_and_own_properties_both_merged(self, tmp_path) -> None:
        """allOf *and* the schema's own properties declared at once."""
        schema = {
            "allOf": [{"$ref": "#/components/schemas/Base"}],
            "type": "object",
            "properties": {"qty": {"type": "integer"}},
        }
        path = _write(tmp_path, "spec.json", json.dumps(_body_request_spec(schema)))
        endpoints = import_openapi_spec(path, _BASE_URL)
        assert endpoints[0].json_requests[0].body == {"name": "gadget", "qty": 1}

    def test_one_of_picks_first_variant(self, tmp_path) -> None:
        schema = {
            "oneOf": [
                {"type": "object", "properties": {"a": {"type": "string"}}},
                {"type": "object", "properties": {"b": {"type": "integer"}}},
            ]
        }
        path = _write(tmp_path, "spec.json", json.dumps(_body_request_spec(schema)))
        endpoints = import_openapi_spec(path, _BASE_URL)
        assert endpoints[0].json_requests[0].body == {"a": "example"}

    def test_any_of_picks_first_variant(self, tmp_path) -> None:
        schema = {"anyOf": [{"type": "integer"}, {"type": "string"}]}
        path = _write(tmp_path, "spec.json", json.dumps(_body_request_spec(schema)))
        endpoints = import_openapi_spec(path, _BASE_URL)
        assert endpoints[0].json_requests[0].body == 1


# ─────────────────────────────────────────────────────────────────────────────
# Fetching a spec directly from an http(s):// URL
# ─────────────────────────────────────────────────────────────────────────────


class TestFetchFromUrl:
    def test_openapi_spec_fetched_from_url(self) -> None:
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        body = json.dumps({"openapi": "3.0.0", "paths": {"/widgets": {"get": {}}}}).encode()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/openapi.json"
            endpoints = import_openapi_spec(url, _BASE_URL)
            assert len(endpoints) == 1
            assert endpoints[0].url == f"{_BASE_URL}/widgets"
        finally:
            server.shutdown()

    def test_fetch_failure_returns_empty(self) -> None:
        # Nothing listens on this port — a connection error, not a hang or a crash.
        assert import_openapi_spec("http://127.0.0.1:1/openapi.json", _BASE_URL) == []

    def test_http_error_status_returns_empty(self) -> None:
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(404)
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/openapi.json"
            assert import_openapi_spec(url, _BASE_URL) == []
        finally:
            server.shutdown()


# ─────────────────────────────────────────────────────────────────────────────
# Swagger 2.0
# ─────────────────────────────────────────────────────────────────────────────


class TestSwagger2:
    def test_body_parameter_in_shape(self, tmp_path) -> None:
        spec = {
            "swagger": "2.0",
            "paths": {
                "/login": {
                    "post": {
                        "parameters": [
                            {
                                "name": "credentials",
                                "in": "body",
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string", "example": "bob"}
                                    },
                                },
                            }
                        ]
                    }
                }
            },
        }
        path = _write(tmp_path, "spec.json", json.dumps(spec))
        endpoints = import_openapi_spec(path, _BASE_URL)
        assert endpoints[0].json_requests[0].body == {"username": "bob"}

    def test_definitions_ref_resolved(self, tmp_path) -> None:
        spec = {
            "swagger": "2.0",
            "paths": {
                "/login": {
                    "post": {
                        "parameters": [
                            {
                                "name": "credentials",
                                "in": "body",
                                "schema": {"$ref": "#/definitions/Credentials"},
                            }
                        ]
                    }
                }
            },
            "definitions": {
                "Credentials": {
                    "type": "object",
                    "properties": {"username": {"type": "string"}},
                }
            },
        }
        path = _write(tmp_path, "spec.json", json.dumps(spec))
        endpoints = import_openapi_spec(path, _BASE_URL)
        assert endpoints[0].json_requests[0].body == {"username": "example"}


# ─────────────────────────────────────────────────────────────────────────────
# Postman Collection v2.1
# ─────────────────────────────────────────────────────────────────────────────


class TestPostmanCollection:
    _COLLECTION = {
        "info": {"name": "Demo"},
        "item": [
            {
                "name": "Get widget",
                "request": {
                    "method": "GET",
                    "url": {
                        "raw": "{{baseUrl}}/api/widgets/:id",
                        "path": ["api", "widgets", ":id"],
                        "query": [{"key": "verbose", "value": "true"}],
                    },
                },
            },
            {
                "name": "a folder",
                "item": [
                    {
                        "name": "Create widget",
                        "request": {
                            "method": "POST",
                            "url": {"raw": "{{baseUrl}}/api/widgets", "path": ["api", "widgets"]},
                            "body": {"mode": "raw", "raw": json.dumps({"qty": 3, "name": "gadget"})},
                        },
                    }
                ],
            },
        ],
    }

    def test_path_variable_becomes_fuzzable_placeholder(self, tmp_path) -> None:
        path = _write(tmp_path, "collection.json", json.dumps(self._COLLECTION))
        endpoints = import_postman_collection(path, _BASE_URL)
        urls = {ep.url for ep in endpoints}
        assert f"{_BASE_URL}/api/widgets/1" in urls

    def test_query_param_from_url_object(self, tmp_path) -> None:
        path = _write(tmp_path, "collection.json", json.dumps(self._COLLECTION))
        endpoints = import_postman_collection(path, _BASE_URL)
        get_endpoint = next(ep for ep in endpoints if ep.url.endswith("/widgets/1"))
        assert get_endpoint.query_params == {"verbose": ["true"]}

    def test_nested_folder_request_found(self, tmp_path) -> None:
        path = _write(tmp_path, "collection.json", json.dumps(self._COLLECTION))
        endpoints = import_postman_collection(path, _BASE_URL)
        post_endpoint = next(ep for ep in endpoints if ep.json_requests)
        assert post_endpoint.json_requests[0].body == {"qty": 3, "name": "gadget"}
        assert post_endpoint.json_requests[0].method == "POST"

    def test_disabled_query_param_skipped(self, tmp_path) -> None:
        collection = {
            "item": [
                {
                    "request": {
                        "method": "GET",
                        "url": {
                            "raw": "{{baseUrl}}/search",
                            "path": ["search"],
                            "query": [
                                {"key": "q", "value": "hello"},
                                {"key": "debug", "value": "1", "disabled": True},
                            ],
                        },
                    }
                }
            ]
        }
        path = _write(tmp_path, "collection.json", json.dumps(collection))
        endpoints = import_postman_collection(path, _BASE_URL)
        assert endpoints[0].query_params == {"q": ["hello"]}

    def test_non_json_body_falls_back_to_query_endpoint(self, tmp_path) -> None:
        collection = {
            "item": [
                {
                    "request": {
                        "method": "POST",
                        "url": {"raw": "{{baseUrl}}/upload", "path": ["upload"]},
                        "body": {"mode": "raw", "raw": "not valid json"},
                    }
                }
            ]
        }
        path = _write(tmp_path, "collection.json", json.dumps(collection))
        endpoints = import_postman_collection(path, _BASE_URL)
        assert endpoints[0].json_requests == []

    def test_missing_file_returns_empty(self) -> None:
        assert import_postman_collection("/nonexistent/collection.json", _BASE_URL) == []

    def test_no_item_key_returns_empty(self, tmp_path) -> None:
        path = _write(tmp_path, "collection.json", json.dumps({"info": {"name": "Demo"}}))
        assert import_postman_collection(path, _BASE_URL) == []
