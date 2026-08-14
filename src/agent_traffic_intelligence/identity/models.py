"""Immutable identity-verification domain models."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from agent_traffic_intelligence.models import VerificationState


class VerificationMethod(StrEnum):
    """Independent mechanisms that can contribute identity evidence."""

    OFFICIAL_RANGE = "official_range"
    FCRDNS = "fcrdns"
    RFC9421 = "rfc9421"
    WEB_BOT_AUTH = "web_bot_auth"


class VerificationOutcome(StrEnum):
    """Per-method result without collapsing operational failures into mismatches."""

    PASS = "pass"
    MISMATCH = "mismatch"
    UNAVAILABLE = "unavailable"
    INDETERMINATE = "indeterminate"
    STALE = "stale"
    ERROR = "error"


class BindingScope(StrEnum):
    """How specifically verification evidence binds an authenticated subject."""

    KEY = "key"
    PROVIDER = "provider"
    AGENT = "agent"


class SourceAddressProvenance(StrEnum):
    """Trust origin for the source address supplied to network verification."""

    DIRECT_PEER = "direct_peer"
    TRUSTED_EDGE_CLIENT = "trusted_edge_client"
    FORWARDED_UNTRUSTED = "forwarded_untrusted"
    UNKNOWN = "unknown"


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class VerificationEvidence:
    """Privacy-safe evidence emitted by one verification mechanism."""

    method: VerificationMethod
    outcome: VerificationOutcome
    binding_scope: BindingScope
    authority: str | None
    subject: str | None
    explanation: str
    source_uri: str | None
    source_profile: str | None
    retrieved_at: datetime | None
    expires_at: datetime | None
    source_sha256: str | None
    details: Mapping[str, str | int | float | bool | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.explanation:
            raise ValueError("explanation must not be empty")
        if self.retrieved_at is not None:
            _require_aware(self.retrieved_at, "retrieved_at")
        if self.expires_at is not None:
            _require_aware(self.expires_at, "expires_at")
        if self.source_sha256 is not None:
            digest = self.source_sha256.casefold()
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise ValueError("source_sha256 must be a 64-character hexadecimal SHA-256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method.value,
            "outcome": self.outcome.value,
            "binding_scope": self.binding_scope.value,
            "authority": self.authority,
            "subject": self.subject,
            "explanation": self.explanation,
            "source_uri": self.source_uri,
            "source_profile": self.source_profile,
            "retrieved_at": self.retrieved_at.isoformat() if self.retrieved_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "source_sha256": self.source_sha256,
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class VerificationResolution:
    """Versioned identity-resolution payload attached to a future V1 detection."""

    state: VerificationState
    provider_verified: bool
    agent_verified: bool
    provider: str | None
    agent: str | None
    methods: tuple[VerificationEvidence, ...]
    conflicts: tuple[str, ...]
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported verification schema version")
        if self.agent_verified and not self.provider_verified:
            raise ValueError("agent verification requires provider verification")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "state": self.state.value,
            "provider_verified": self.provider_verified,
            "agent_verified": self.agent_verified,
            "provider": self.provider,
            "agent": self.agent,
            "methods": [item.to_dict() for item in self.methods],
            "conflicts": list(self.conflicts),
        }
