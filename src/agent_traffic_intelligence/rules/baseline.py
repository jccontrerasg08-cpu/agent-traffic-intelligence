"""Conservative V0 hand-authored evidence rules."""

from __future__ import annotations

import re
from collections.abc import Mapping

from agent_traffic_intelligence.models import Evidence, RequestEvent
from agent_traffic_intelligence.registry import RegistryEntry

_GENERIC_BOT_RE = re.compile(r"(?:bot|crawler|spider|scrapy|headless)", re.IGNORECASE)


def identity_evidence(event: RequestEvent, entry: RegistryEntry | None) -> list[Evidence]:
    """Create evidence from claimed User-Agent identities without over-verifying them."""

    evidence: list[Evidence] = []
    if entry is not None:
        evidence.append(
            Evidence(
                code="known-agent-ua-claim",
                source="registry",
                description=(
                    f"User-Agent claims the curated {entry.provider}/{entry.agent} identity; "
                    "User-Agent alone is spoofable and is not verification."
                ),
                strength=1.0,
                score_deltas={
                    "automation": 4.0,
                    "ai": 4.6 if entry.ai_related else -0.5,
                    "identity": 0.8,
                    "risk": 0.0,
                },
            )
        )
    elif event.user_agent and _GENERIC_BOT_RE.search(event.user_agent):
        evidence.append(
            Evidence(
                code="generic-automation-ua",
                source="user-agent",
                description="User-Agent contains a common automation token but has no verified identity.",
                strength=1.0,
                score_deltas={"automation": 1.3, "ai": 0.0, "identity": 0.0, "risk": 0.1},
            )
        )
    return evidence


def behavior_evidence(features: Mapping[str, float | int | bool | str | None]) -> list[Evidence]:
    """Create cautious behavioral evidence after sufficient session observations."""

    evidence: list[Evidence] = []
    count = int(features.get("session_request_count", 0) or 0)
    if count < 5:
        return evidence

    asset_ratio = float(features.get("asset_ratio", 0.0) or 0.0)
    if asset_ratio <= 0.10:
        evidence.append(
            Evidence(
                code="html-heavy-session",
                source="behavior",
                description="Session requested almost no static/browser assets across multiple requests.",
                strength=1.0,
                score_deltas={"automation": 1.25, "ai": 0.0, "identity": 0.0, "risk": 0.15},
            )
        )

    mean_interval = float(features.get("mean_interarrival_seconds", 0.0) or 0.0)
    interval_cv = float(features.get("interarrival_cv", 0.0) or 0.0)
    if mean_interval > 0 and interval_cv <= 0.10:
        evidence.append(
            Evidence(
                code="regular-request-cadence",
                source="behavior",
                description="Inter-request timing is unusually regular for the observed session window.",
                strength=1.0,
                score_deltas={"automation": 0.8, "ai": 0.0, "identity": 0.0, "risk": 0.1},
            )
        )

    error_ratio = float(features.get("error_ratio", 0.0) or 0.0)
    if count >= 6 and error_ratio >= 0.50:
        evidence.append(
            Evidence(
                code="high-error-ratio",
                source="behavior",
                description="A high fraction of session requests returned client/server errors.",
                strength=1.0,
                score_deltas={"automation": 0.5, "ai": 0.0, "identity": 0.0, "risk": 3.0},
            )
        )

    requests_per_minute = float(features.get("requests_per_minute", 0.0) or 0.0)
    if count >= 10 and requests_per_minute >= 120:
        evidence.append(
            Evidence(
                code="high-request-rate",
                source="behavior",
                description="Session request rate exceeds the conservative V0 high-rate threshold.",
                strength=1.0,
                score_deltas={"automation": 0.7, "ai": 0.0, "identity": 0.0, "risk": 1.5},
            )
        )

    browser_context_signals = sum(
        bool(features.get(name))
        for name in ("has_cookie", "has_referer", "has_accept_language")
    )
    if browser_context_signals == 3 and asset_ratio >= 0.20:
        evidence.append(
            Evidence(
                code="browser-context-present",
                source="behavior",
                description="Session exhibits multiple normal browser context and asset-loading signals.",
                strength=1.0,
                score_deltas={"automation": -0.5, "ai": 0.0, "identity": 0.0, "risk": -0.2},
            )
        )

    return evidence
