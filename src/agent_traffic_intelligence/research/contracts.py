"""Privacy-first contracts for research tracks proposed but not yet activated."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ResearchTrack(StrEnum):
    """Independent research directions that must not alter the core by default."""

    NETWORK_FINGERPRINT = "network_fingerprint"
    UNKNOWN_DISCOVERY = "unknown_discovery"
    CONTROLLED_BENCHMARK = "controlled_benchmark"
    ATTRIBUTION_GRAPH = "attribution_graph"
    API_ABUSE = "api_abuse"
    EBPF_SENSOR = "ebpf_sensor"
    BROWSER_LAB = "browser_lab"


class ResearchReadiness(StrEnum):
    """Evidence gate for a research track before it can supply active evidence."""

    DOCUMENTED = "documented"
    BLOCKED = "blocked"
    READY_FOR_REVIEW = "ready_for_review"


@dataclass(frozen=True, slots=True)
class ResearchCase:
    """Minimal declaration required before a research variant is enabled."""

    track: ResearchTrack
    readiness: ResearchReadiness
    owner: str
    authorization_reference: str | None
    data_categories: tuple[str, ...]
    retention_policy: str
    evaluation_metrics: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.owner.strip():
            raise ValueError("owner must not be blank")
        if not self.data_categories:
            raise ValueError("data_categories must not be empty")
        if not self.retention_policy.strip():
            raise ValueError("retention_policy must not be blank")
        if not self.evaluation_metrics:
            raise ValueError("evaluation_metrics must not be empty")
        if self.readiness is ResearchReadiness.READY_FOR_REVIEW and (
            self.authorization_reference is None or not self.authorization_reference.strip()
        ):
            raise ValueError("ready research cases require an authorization reference")
