"""Contract tests for the unauthenticated response-only observation routes."""

from __future__ import annotations

import json

from test_service import request, running_service

from agent_traffic_intelligence.service import ServiceConfig


def test_public_catalog_requires_no_token_and_exposes_only_capability_contract() -> None:
    config = ServiceConfig(host="127.0.0.1", port=0, api_token="never-expose-this")

    with running_service(config) as (host, port):
        status, payload = request(host, port, "GET", "/v1/catalog?probe=never-return-this")

    assert status == 200
    assert payload["access"] == {
        "authentication": "not_required",
        "persistence": "none",
        "ui": "none",
    }
    assert payload["client_classes"]["declared_supported"] == [
        "ai",
        "automation",
        "bot",
        "human",
    ]
    assert "never-expose-this" not in json.dumps(payload)


def test_public_observation_reports_declarations_not_identity_or_dns_resolution() -> None:
    config = ServiceConfig(host="127.0.0.1", port=0, api_token="controlled-test-token")
    headers = {
        "Accept-Encoding": "gzip",
        "Accept-Language": "es-MX",
        "Forwarded": "for=203.0.113.9;proto=https",
        "Sec-CH-UA": '"Example";v="1"',
        "User-Agent": "ExampleBot/1.0",
        "X-ATI-Client-Class": "ai",
    }

    with running_service(config) as (host, port):
        status, payload = request(
            host,
            port,
            "GET",
            "/v1/observe?email=must-not-be-returned",
            headers=headers,
        )

    assert status == 200
    assert payload["persistence"] == "none"
    assert payload["observation"] == {
        "accept_encoding_declared": True,
        "accept_language_declared": True,
        "client_hints_declared": True,
        "client_identity": "not_verified",
        "client_intent": "not_observable",
        "content_length_declared": False,
        "content_type_declared": False,
        "declared_client_class": "ai",
        "dns_resolution": "not_observable_over_http",
        "forwarded_header_state": "present_but_untrusted",
        "user_agent_declared": True,
    }
    serialized = json.dumps(payload)
    assert "203.0.113.9" not in serialized
    assert "ExampleBot/1.0" not in serialized
    assert "must-not-be-returned" not in serialized


def test_public_observation_downgrades_unknown_client_class_to_unspecified() -> None:
    config = ServiceConfig(host="127.0.0.1", port=0)

    with running_service(config) as (host, port):
        status, payload = request(
            host,
            port,
            "GET",
            "/v1/observe",
            headers={"X-ATI-Client-Class": "super-agent"},
        )

    assert status == 200
    assert payload["observation"]["declared_client_class"] == "unspecified"
    assert payload["observation"]["forwarded_header_state"] == "not_present"


def test_public_observation_rejects_write_methods_without_reading_any_body() -> None:
    config = ServiceConfig(host="127.0.0.1", port=0)

    with running_service(config) as (host, port):
        status, payload = request(host, port, "POST", "/v1/observe", body="ignored")

    assert status == 404
    assert payload == {"error": "not_found"}
