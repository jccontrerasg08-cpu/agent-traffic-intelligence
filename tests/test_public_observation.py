"""Contract tests for the unauthenticated response-only observation routes."""

from __future__ import annotations

import json

import pytest
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
    assert payload["catalog_version"] == "2"
    assert payload["client_classes"]["declared_supported"] == [
        "ai",
        "automation",
        "bot",
        "human",
    ]
    assert payload["dimensions"]["controlled_iteration"] == "declared_experiment_only"
    assert payload["dimensions"]["interaction_mode"] == "declared_category_only"
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
        "controlled_iteration": "not_declared",
        "content_length_declared": False,
        "content_type_declared": False,
        "declared_client_class": "ai",
        "dns_resolution": "not_observable_over_http",
        "forwarded_header_state": "present_but_untrusted",
        "interaction_mode": "unspecified",
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


@pytest.mark.parametrize(
    ("client_class", "iteration", "interaction_mode", "expected_iteration"),
    [
        ("human", "1", "silent", "first_declared"),
        ("ai", "2", "text", "repeat_declared"),
        ("bot", "3", "tool_call", "repeat_declared"),
        ("automation", "4", "mixed", "repeat_declared"),
    ],
)
def test_public_observation_normalizes_controlled_experiment_declarations(
    client_class: str,
    iteration: str,
    interaction_mode: str,
    expected_iteration: str,
) -> None:
    config = ServiceConfig(host="127.0.0.1", port=0)
    headers = {
        "X-ATI-Client-Class": client_class,
        "X-ATI-Interaction-Mode": interaction_mode,
        "X-ATI-Observation-Iteration": iteration,
    }

    with running_service(config) as (host, port):
        status, payload = request(host, port, "GET", "/v1/observe", headers=headers)

    assert status == 200
    assert payload["schema_version"] == "2"
    assert payload["persistence"] == "none"
    assert payload["observation"]["declared_client_class"] == client_class
    assert payload["observation"]["controlled_iteration"] == expected_iteration
    assert payload["observation"]["interaction_mode"] == interaction_mode
    assert payload["observation"]["client_identity"] == "not_verified"
    assert payload["observation"]["client_intent"] == "not_observable"


def test_public_observation_accepts_intermediary_header_capitalization() -> None:
    config = ServiceConfig(host="127.0.0.1", port=0)
    headers = {
        "x-ati-client-class": "ai",
        "X-Ati-Interaction-Mode": "tool_call",
        "x-Ati-Observation-Iteration": "2",
    }

    with running_service(config) as (host, port):
        status, payload = request(host, port, "GET", "/v1/observe", headers=headers)

    assert status == 200
    assert payload["observation"]["declared_client_class"] == "ai"
    assert payload["observation"]["controlled_iteration"] == "repeat_declared"
    assert payload["observation"]["interaction_mode"] == "tool_call"


def test_public_observation_rejects_invalid_control_declarations_without_reflection() -> None:
    config = ServiceConfig(host="127.0.0.1", port=0)
    headers = {
        "X-ATI-Interaction-Mode": "send-this-content-now",
        "X-ATI-Observation-Iteration": "round-9000",
    }

    with running_service(config) as (host, port):
        status, payload = request(host, port, "GET", "/v1/observe", headers=headers)

    assert status == 200
    assert payload["observation"]["controlled_iteration"] == "invalid_declaration"
    assert payload["observation"]["interaction_mode"] == "unspecified"
    serialized = json.dumps(payload)
    assert "round-9000" not in serialized
    assert "send-this-content-now" not in serialized


def test_public_observation_rejects_write_methods_without_reading_any_body() -> None:
    config = ServiceConfig(host="127.0.0.1", port=0)

    with running_service(config) as (host, port):
        status, payload = request(host, port, "POST", "/v1/observe", body="ignored")

    assert status == 404
    assert payload == {"error": "not_found"}
