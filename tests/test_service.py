"""Tests for the no-UI, observe-only Railway service adapter."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from http.client import HTTPConnection
from threading import Thread

from agent_traffic_intelligence.service import ServiceConfig, create_server, main


@contextmanager
def running_service(config: ServiceConfig) -> Iterator[tuple[str, int]]:
    server = create_server(config)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield host, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    body: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, object]]:
    connection = HTTPConnection(host, port, timeout=2)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def test_health_requires_no_token_and_never_exposes_configuration_secret() -> None:
    config = ServiceConfig(host="127.0.0.1", port=0, api_token="do-not-expose")

    with running_service(config) as (host, port):
        status, payload = request(host, port, "GET", "/health")

    assert status == 200
    assert payload["status"] == "ok"
    assert payload["mode"] == "observe-only"
    assert payload["analysis_endpoint"] == "enabled"
    assert "do-not-expose" not in json.dumps(payload)


def test_analysis_endpoint_is_disabled_without_explicit_service_token() -> None:
    config = ServiceConfig(host="127.0.0.1", port=0)

    with running_service(config) as (host, port):
        status, payload = request(host, port, "POST", "/v1/analyze", body="{}\n")

    assert status == 503
    assert payload == {"error": "analysis_endpoint_disabled"}


def test_authorized_analysis_returns_only_privacy_safe_detections() -> None:
    config = ServiceConfig(
        host="127.0.0.1",
        port=0,
        api_token="controlled-test-token",
        hash_key=b"test-hash-key",
    )
    source = json.dumps(
        {
            "time_iso8601": "2026-08-19T12:00:00+00:00",
            "remote_addr": "203.0.113.9",
            "request_method": "GET",
            "request_uri": "/docs?token=never-return-this",
            "status": 200,
            "body_bytes_sent": 100,
            "server_protocol": "HTTP/2",
            "http_user_agent": "Mozilla/5.0 compatible; GPTBot/1.0",
        }
    ) + "\n"

    with running_service(config) as (host, port):
        unauthorized_status, unauthorized_payload = request(
            host, port, "POST", "/v1/analyze", body=source
        )
        status, payload = request(
            host,
            port,
            "POST",
            "/v1/analyze",
            body=source,
            headers={
                "Authorization": "Bearer controlled-test-token",
                "Content-Type": "application/x-ndjson",
            },
        )

    assert unauthorized_status == 401
    assert unauthorized_payload == {"error": "unauthorized"}
    assert status == 200
    assert payload["processed"] == 1
    serialized = json.dumps(payload)
    assert "203.0.113.9" not in serialized
    assert "never-return-this" not in serialized
    assert payload["detections"][0]["identity"]["agent"] == "GPTBot"


def test_authorized_analysis_rejects_empty_batches() -> None:
    config = ServiceConfig(host="127.0.0.1", port=0, api_token="controlled-test-token")

    with running_service(config) as (host, port):
        status, payload = request(
            host,
            port,
            "POST",
            "/v1/analyze",
            body="\n",
            headers={
                "Authorization": "Bearer controlled-test-token",
                "Content-Type": "application/x-ndjson",
            },
        )

    assert status == 400
    assert payload == {"error": "request_body_contains_no_events"}


def test_authorized_analysis_requires_the_declared_jsonl_content_type() -> None:
    config = ServiceConfig(host="127.0.0.1", port=0, api_token="controlled-test-token")

    with running_service(config) as (host, port):
        status, payload = request(
            host,
            port,
            "POST",
            "/v1/analyze",
            body="{}\n",
            headers={
                "Authorization": "Bearer controlled-test-token",
                "Content-Type": "application/json",
            },
        )

    assert status == 400
    assert payload == {"error": "content_type_must_be_application_x_ndjson"}


def test_service_main_reports_bind_failure_without_traceback(monkeypatch, capsys) -> None:
    def fail_to_bind() -> object:
        raise OSError("address already in use")

    monkeypatch.setattr("agent_traffic_intelligence.service.create_server", fail_to_bind)

    assert main() == 2
    assert capsys.readouterr().out == "error: address already in use\n"
