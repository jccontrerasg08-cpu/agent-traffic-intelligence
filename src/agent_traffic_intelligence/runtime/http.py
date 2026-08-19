"""Minimal HTTP protocol adapter for authorized, bounded JSONL analysis."""

from __future__ import annotations

import hmac
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from agent_traffic_intelligence import __version__
from agent_traffic_intelligence.engine import Detector
from agent_traffic_intelligence.features.session import SessionFeatureState
from agent_traffic_intelligence.parsers.jsonl import ParseError, iter_jsonl
from agent_traffic_intelligence.runtime.config import ServiceConfig
from agent_traffic_intelligence.runtime.public_observation import (
    PUBLIC_CATALOG,
    PublicObservation,
)


class ServiceRequestError(ValueError):
    """Raised when an authorized batch violates a bounded request contract."""


class AtiServiceHTTPServer(ThreadingHTTPServer):
    """Threaded standard-library server carrying immutable service configuration."""

    daemon_threads = True

    def __init__(self, config: ServiceConfig) -> None:
        self.config = config
        super().__init__((config.host, config.port), AtiServiceHandler)


class AtiServiceHandler(BaseHTTPRequestHandler):
    """Serve health and analysis requests without logging request content."""

    server: AtiServiceHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        """Avoid logging client addresses, headers, paths, or payload hints."""

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/health":
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
            return
        if path == "/v1/catalog":
            self._json(HTTPStatus.OK, PUBLIC_CATALOG)
            return
        if path == "/v1/observe":
            self._json(
                HTTPStatus.OK,
                {
                    "observation": PublicObservation.from_headers(
                        dict(self.headers.items())
                    ).to_dict(),
                    "persistence": "none",
                    "schema_version": "1",
                },
            )
            return
        self._json_error(HTTPStatus.NOT_FOUND, "not_found")

    def do_POST(self) -> None:
        if urlsplit(self.path).path != "/v1/analyze":
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
