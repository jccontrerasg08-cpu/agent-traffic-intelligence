"""Bounded observe-only HTTP adapter for authorized JSONL analysis batches.

The adapter deliberately exposes no browser UI, no blocking decision, no traffic
mutation, no source refresh, and no durable request/detection storage. It exists
only to make the deterministic CLI core callable from an explicitly configured
service process such as Railway.
"""

from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from agent_traffic_intelligence import __version__
from agent_traffic_intelligence.engine import Detector
from agent_traffic_intelligence.features.session import SessionFeatureState
from agent_traffic_intelligence.parsers.jsonl import (
    DEFAULT_MAX_LINE_CHARACTERS,
    ParseError,
    iter_jsonl,
)

DEFAULT_PORT = 8080
DEFAULT_MAX_BATCH_EVENTS = 1_000
DEFAULT_MAX_REQUEST_BYTES = 10_000_000


class ServiceConfigurationError(ValueError):
    """Raised when required service configuration is malformed."""


class ServiceRequestError(ValueError):
    """Raised when an authorized batch violates a bounded request contract."""


def _bounded_int(name: str, *, default: int, minimum: int, maximum: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ServiceConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise ServiceConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return parsed


@dataclass(frozen=True)
class ServiceConfig:
    """Operational limits for the bounded technical service."""

    host: str = "0.0.0.0"
    port: int = DEFAULT_PORT
    api_token: str | None = None
    hash_key: bytes | None = None
    max_batch_events: int = DEFAULT_MAX_BATCH_EVENTS
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    max_line_characters: int = DEFAULT_MAX_LINE_CHARACTERS
    max_clients: int = 10_000
    max_events_per_client: int = 128
    session_window_seconds: int = 900

    @property
    def analysis_enabled(self) -> bool:
        """Require an explicit shared secret before accepting any log data."""

        return self.api_token is not None

    @classmethod
    def from_environment(cls) -> ServiceConfig:
        token = os.environ.get("ATI_SERVICE_TOKEN")
        if token is not None and not token.strip():
            raise ServiceConfigurationError("ATI_SERVICE_TOKEN must not be blank")

        hash_key_text = os.environ.get("ATI_HASH_KEY")
        hash_key = hash_key_text.encode("utf-8") if hash_key_text else None
        if hash_key is not None and len(hash_key) > 64:
            raise ServiceConfigurationError("ATI_HASH_KEY exceeds the 64-byte BLAKE2b key limit")

        host = os.environ.get("ATI_SERVICE_HOST", "0.0.0.0")
        if not host.strip():
            raise ServiceConfigurationError("ATI_SERVICE_HOST must not be blank")

        return cls(
            host=host,
            port=_bounded_int("PORT", default=DEFAULT_PORT, minimum=1, maximum=65535),
            api_token=token,
            hash_key=hash_key,
            max_batch_events=_bounded_int(
                "ATI_MAX_BATCH_EVENTS",
                default=DEFAULT_MAX_BATCH_EVENTS,
                minimum=1,
                maximum=100_000,
            ),
            max_request_bytes=_bounded_int(
                "ATI_MAX_REQUEST_BYTES",
                default=DEFAULT_MAX_REQUEST_BYTES,
                minimum=1,
                maximum=100_000_000,
            ),
            max_line_characters=_bounded_int(
                "ATI_MAX_LINE_CHARACTERS",
                default=DEFAULT_MAX_LINE_CHARACTERS,
                minimum=1,
                maximum=10_000_000,
            ),
            max_clients=_bounded_int(
                "ATI_MAX_CLIENTS", default=10_000, minimum=1, maximum=1_000_000
            ),
            max_events_per_client=_bounded_int(
                "ATI_MAX_EVENTS_PER_CLIENT", default=128, minimum=1, maximum=10_000
            ),
            session_window_seconds=_bounded_int(
                "ATI_SESSION_WINDOW_SECONDS", default=900, minimum=1, maximum=86_400
            ),
        )


class AtiServiceHTTPServer(ThreadingHTTPServer):
    """Threaded standard-library server carrying immutable service configuration."""

    daemon_threads = True

    def __init__(self, config: ServiceConfig) -> None:
        self.config = config
        super().__init__((config.host, config.port), AtiServiceHandler)


class AtiServiceHandler(BaseHTTPRequestHandler):
    """Serve health and bounded analysis requests without logging request contents."""

    server: AtiServiceHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        """Do not write client address, path, headers, or payload hints to stdout."""

    def do_GET(self) -> None:
        if self.path != "/health":
            self._json_error(HTTPStatus.NOT_FOUND, "not_found")
            return
        self._json(
            HTTPStatus.OK,
            {
                "status": "ok",
                "mode": "observe-only",
                "analysis_endpoint": (
                    "enabled" if self.server.config.analysis_enabled else "disabled"
                ),
                "persistence": "none",
                "version": __version__,
            },
        )

    def do_POST(self) -> None:
        if self.path != "/v1/analyze":
            self._json_error(HTTPStatus.NOT_FOUND, "not_found")
            return
        config = self.server.config
        if not config.analysis_enabled:
            self._json_error(HTTPStatus.SERVICE_UNAVAILABLE, "analysis_endpoint_disabled")
            return
        if not self._authorized(config):
            self._json_error(HTTPStatus.UNAUTHORIZED, "unauthorized")
            return
        try:
            payload = self._read_body(config)
            detections = self._analyze(payload, config)
        except ServiceRequestError as exc:
            self._json_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        except ParseError as exc:
            self._json_error(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc))
            return
        self._json(HTTPStatus.OK, {"processed": len(detections), "detections": detections})

    def do_PUT(self) -> None:
        self._json_error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

    def do_DELETE(self) -> None:
        self._json_error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

    def _authorized(self, config: ServiceConfig) -> bool:
        assert config.api_token is not None
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {config.api_token}"
        return hmac.compare_digest(supplied, expected)

    def _read_body(self, config: ServiceConfig) -> str:
        content_type = (
            self.headers.get("Content-Type", "").split(";", maxsplit=1)[0].strip().lower()
        )
        if content_type != "application/x-ndjson":
            raise ServiceRequestError("content_type_must_be_application_x_ndjson")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ServiceRequestError("content_length_required")
        try:
            content_length = int(raw_length)
        except ValueError as exc:
            raise ServiceRequestError("invalid_content_length") from exc
        if content_length < 0 or content_length > config.max_request_bytes:
            raise ServiceRequestError("request_body_exceeds_limit")
        try:
            return self.rfile.read(content_length).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ServiceRequestError("request_body_must_be_utf8") from exc

    @staticmethod
    def _analyze(payload: str, config: ServiceConfig) -> list[dict[str, Any]]:
        detector = Detector(
            session_state=SessionFeatureState(
                max_clients=config.max_clients,
                max_events_per_client=config.max_events_per_client,
                window_seconds=config.session_window_seconds,
            )
        )
        detections: list[dict[str, Any]] = []
        for event in iter_jsonl(
            payload.splitlines(keepends=True),
            hash_key=config.hash_key,
            source="service-jsonl",
            max_line_characters=config.max_line_characters,
        ):
            if len(detections) >= config.max_batch_events:
                raise ServiceRequestError("batch_event_limit_exceeded")
            detections.append(detector.detect(event).to_dict())
        if not detections:
            raise ServiceRequestError("request_body_contains_no_events")
        return detections

    def _json_error(self, status: HTTPStatus, code: str) -> None:
        self._json(status, {"error": code})

    def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def create_server(config: ServiceConfig | None = None) -> AtiServiceHTTPServer:
    """Create a server without starting it, primarily for controlled tests."""

    return AtiServiceHTTPServer(config or ServiceConfig.from_environment())


def main() -> int:
    """Run the technical service until Railway or an operator sends SIGTERM."""

    try:
        server = create_server()
    except (OSError, ServiceConfigurationError) as exc:
        print(f"error: {exc}")
        return 2
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
