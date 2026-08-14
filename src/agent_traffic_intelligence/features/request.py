"""Request-local feature extraction."""

from __future__ import annotations

from pathlib import PurePosixPath

from agent_traffic_intelligence.models import RequestEvent

_ASSET_SUFFIXES = frozenset(
    {
        ".avif",
        ".css",
        ".eot",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".json",
        ".map",
        ".mjs",
        ".mp4",
        ".png",
        ".svg",
        ".ttf",
        ".webm",
        ".webp",
        ".woff",
        ".woff2",
    }
)


def is_asset_path(path: str) -> bool:
    """Return whether a path looks like a static/browser asset."""

    return PurePosixPath(path.casefold()).suffix in _ASSET_SUFFIXES


def path_depth(path: str) -> int:
    """Count non-empty URL path segments."""

    return sum(1 for segment in path.split("/") if segment)


def request_features(event: RequestEvent) -> dict[str, float | int | bool]:
    """Extract deterministic, non-sensitive request-local features."""

    return {
        "path_depth": path_depth(event.path),
        "is_asset": is_asset_path(event.path),
        "is_error": event.status >= 400,
        "has_cookie": event.has_cookie,
        "has_referer": event.has_referer,
        "has_accept_language": event.has_accept_language,
    }
