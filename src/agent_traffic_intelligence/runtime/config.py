"""Bounded, non-secret configuration for the observe-only HTTP adapter."""

from __future__ import annotations

import os
from dataclasses import dataclass

from agent_traffic_intelligence.parsers.jsonl import DEFAULT_MAX_LINE_CHARACTERS

DEFAULT_PORT = 8080
DEFAULT_MAX_BATCH_EVENTS = 1_000
DEFAULT_MAX_REQUEST_BYTES = 10_000_000


class ServiceConfigurationError(ValueError):
    """Raised when service configuration is malformed or unsafe."""


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
        """Load only the bounded runtime contract from environment variables."""

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
