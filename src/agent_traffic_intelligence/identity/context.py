"""Ephemeral inputs used only during identity verification."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from agent_traffic_intelligence.identity.models import SourceAddressProvenance


@dataclass(frozen=True, slots=True)
class VerificationContext:
    """Non-serializable request material that must not survive verification."""

    source_ip: str | None
    source_address_provenance: SourceAddressProvenance
    authority: str | None
    method: str
    target_uri: str | None
    signature: str | None
    signature_input: str | None
    signature_agent: str | None
    covered_headers: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.method:
            raise ValueError("method must not be empty")
        object.__setattr__(
            self, "covered_headers", MappingProxyType(dict(self.covered_headers))
        )
