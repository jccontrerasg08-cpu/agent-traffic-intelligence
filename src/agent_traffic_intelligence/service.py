"""Backward-compatible facade for ATI's modular observe-only service runtime.

New runtime code lives under :mod:`agent_traffic_intelligence.runtime`.  This
module keeps the `ati-service` entrypoint and existing imports stable while
making the compatibility boundary explicit.
"""

from __future__ import annotations

from agent_traffic_intelligence.runtime.config import ServiceConfig, ServiceConfigurationError
from agent_traffic_intelligence.runtime.http import (
    AtiServiceHandler,
    AtiServiceHTTPServer,
    ServiceRequestError,
)
from agent_traffic_intelligence.runtime.server import create_server as _create_server
from agent_traffic_intelligence.runtime.server import run_server

__all__ = [
    "AtiServiceHTTPServer",
    "AtiServiceHandler",
    "ServiceConfig",
    "ServiceConfigurationError",
    "ServiceRequestError",
    "create_server",
    "main",
]


def create_server(config: ServiceConfig | None = None) -> AtiServiceHTTPServer:
    """Create the service through the modular runtime implementation."""

    return _create_server(config)


def main() -> int:
    """Preserve the historical `ati-service` entrypoint and monkeypatch seam."""

    return run_server(create_server)
