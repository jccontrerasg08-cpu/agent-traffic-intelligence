"""Core immutable domain models for Agent Traffic Intelligence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_traffic_intelligence.identity.models import VerificationResolution


class ActorType(StrEnum):
    """High-level actor taxonomy."""

    HUMAN = "human"
    SEARCH_CRAWLER = "search_crawler"
    SERVICE_CRAWLER = "service_crawler"
    AI_CRAWLER = "ai_crawler"
    AI_USER_AGENT = "ai_user_agent"
    BROWSER_AUTOMATION = "browser_automation"
    SCRAPER = "scraper"
    SCANNER = "scanner"
    UNKNOWN_AUTOMATION = "unknown_automation"
    UNKNOWN = "unknown"


class VerificationState(StrEnum):
    """Confidence class for a claimed machine identity."""

    NONE = "none"
    CLAIMED = "claimed"
    VERIFIED = "verified"
    FAILED = "failed"
    CONFLICTED = "conflicted"


@dataclass(frozen=True, slots=True)
class RequestEvent:
    """Privacy-minimized normalized HTTP request."""

    timestamp: datetime
    request_id: str
    client_id: str
    method: str
    path: str
    status: int
    bytes_sent: int
    http_version: str
    user_agent: str | None
    has_referer: bool = False
    has_cookie: bool = False
    has_accept_language: bool = False
    ja4: str | None = None
    source: str = "unknown"

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        if not self.request_id:
            raise ValueError("request_id must not be empty")
        if not self.client_id:
            raise ValueError("client_id must not be empty")
        if not self.method:
            raise ValueError("method must not be empty")
        if not self.path.startswith("/"):
            raise ValueError("path must start with '/'")
        if not 100 <= self.status <= 599:
            raise ValueError("status must be a valid HTTP status")
        if self.bytes_sent < 0:
            raise ValueError("bytes_sent must be non-negative")

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "request_id": self.request_id,
            "client_id": self.client_id,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "bytes_sent": self.bytes_sent,
            "http_version": self.http_version,
            "user_agent": self.user_agent,
            "has_referer": self.has_referer,
            "has_cookie": self.has_cookie,
            "has_accept_language": self.has_accept_language,
            "ja4": self.ja4,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class Evidence:
    """Explainable contribution to one or more score dimensions."""

    code: str
    source: str
    description: str
    strength: float
    score_deltas: Mapping[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not -1.0 <= self.strength <= 1.0:
            raise ValueError("strength must be between -1 and 1")
        if not self.code:
            raise ValueError("code must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "source": self.source,
            "description": self.description,
            "strength": self.strength,
            "score_deltas": dict(self.score_deltas),
        }


@dataclass(frozen=True, slots=True)
class IdentityClaim:
    """An actor identity inferred or verified from request evidence."""

    provider: str
    agent: str
    actor_type: ActorType
    intent: str
    verification_state: VerificationState = VerificationState.CLAIMED

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "agent": self.agent,
            "actor_type": self.actor_type.value,
            "intent": self.intent,
            "verification_state": self.verification_state.value,
        }


@dataclass(frozen=True, slots=True)
class Detection:
    """Detector output for one normalized request."""

    request_id: str
    automation_score: float
    ai_score: float
    identity_confidence: float
    risk_score: float
    identity: IdentityClaim | None
    evidence: tuple[Evidence, ...]
    features: Mapping[str, float | int | bool | str | None]
    ruleset_version: str
    verification: VerificationResolution | None = None

    def __post_init__(self) -> None:
        for name in ("automation_score", "ai_score", "identity_confidence", "risk_score"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": 1,
            "request_id": self.request_id,
            "automation_score": self.automation_score,
            "ai_score": self.ai_score,
            "identity_confidence": self.identity_confidence,
            "risk_score": self.risk_score,
            "identity": self.identity.to_dict() if self.identity else None,
            "evidence": [item.to_dict() for item in self.evidence],
            "features": dict(self.features),
            "ruleset_version": self.ruleset_version,
        }
        if self.verification is not None:
            payload["verification"] = self.verification.to_dict()
        return payload
