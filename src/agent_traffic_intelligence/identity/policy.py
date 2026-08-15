"""Verification execution and remote-discovery policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class VerificationMode(StrEnum):
    OFFLINE = "offline"
    HYBRID = "hybrid"
    LIVE = "live"


class DiscoveryPolicy(StrEnum):
    REGISTRY_ONLY = "registry_only"
    PUBLIC_HTTPS = "public_https"


@dataclass(frozen=True, slots=True)
class VerificationPolicy:
    """Bounded defaults that keep verification offline unless explicitly enabled."""

    mode: VerificationMode = VerificationMode.OFFLINE
    discovery_policy: DiscoveryPolicy = DiscoveryPolicy.REGISTRY_ONLY
    allow_unknown_signature_agent_fetch: bool = False
    max_workers: int = 4
    verifier_timeout_seconds: float = 2.0

    def __post_init__(self) -> None:
        if self.max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        if self.verifier_timeout_seconds <= 0:
            raise ValueError("verifier_timeout_seconds must be positive")
        if (
            self.discovery_policy is DiscoveryPolicy.REGISTRY_ONLY
            and self.allow_unknown_signature_agent_fetch
        ):
            raise ValueError(
                "registry-only discovery cannot allow unknown Signature-Agent fetching"
            )
