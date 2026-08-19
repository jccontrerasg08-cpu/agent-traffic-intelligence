"""Lifecycle functions for the no-UI observe-only service process."""

from __future__ import annotations

from collections.abc import Callable

from agent_traffic_intelligence.runtime.config import ServiceConfig, ServiceConfigurationError
from agent_traffic_intelligence.runtime.http import AtiServiceHTTPServer


def create_server(config: ServiceConfig | None = None) -> AtiServiceHTTPServer:
    """Create a server without starting it, primarily for controlled tests."""

    return AtiServiceHTTPServer(config or ServiceConfig.from_environment())


def run_server(server_factory: Callable[[], AtiServiceHTTPServer]) -> int:
    """Serve until terminated and report startup failures without a traceback."""

    try:
        server = server_factory()
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


def main() -> int:
    """Run the technical service until Railway or an operator sends SIGTERM."""

    return run_server(create_server)
