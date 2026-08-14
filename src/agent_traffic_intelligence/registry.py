"""Auditable registry for known automated-agent identity claims."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_traffic_intelligence.models import ActorType, IdentityClaim, VerificationState


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    token: str
    provider: str
    agent: str
    actor_type: ActorType
    intent: str
    ai_related: bool
    official_source: str
    last_verified: str
    deprecated: bool = False
    supported_until: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RegistryEntry":
        return cls(
            token=str(value["token"]),
            provider=str(value["provider"]),
            agent=str(value["agent"]),
            actor_type=ActorType(str(value["actor_type"])),
            intent=str(value["intent"]),
            ai_related=bool(value["ai_related"]),
            official_source=str(value["official_source"]),
            last_verified=str(value["last_verified"]),
            deprecated=bool(value.get("deprecated", False)),
            supported_until=(
                str(value["supported_until"]) if value.get("supported_until") else None
            ),
        )


class AgentRegistry:
    """Case-insensitive User-Agent token matcher backed by auditable JSON."""

    def __init__(self, entries: tuple[RegistryEntry, ...]) -> None:
        if not entries:
            raise ValueError("registry must contain at least one entry")
        tokens = [entry.token.casefold() for entry in entries]
        if len(tokens) != len(set(tokens)):
            raise ValueError("registry contains duplicate tokens")
        self._entries = entries

    @property
    def entries(self) -> tuple[RegistryEntry, ...]:
        return self._entries

    @classmethod
    def from_path(cls, path: Path) -> "AgentRegistry":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("schema_version") != 1:
            raise ValueError("unsupported registry schema")
        raw_entries = raw.get("entries")
        if not isinstance(raw_entries, list):
            raise ValueError("registry entries must be a list")
        entries = tuple(RegistryEntry.from_dict(item) for item in raw_entries)
        return cls(entries)

    @classmethod
    def default(cls) -> "AgentRegistry":
        return cls.from_path(Path(__file__).with_name("agents.json"))

    def match_entry(self, user_agent: str | None) -> RegistryEntry | None:
        if not user_agent:
            return None
        folded = user_agent.casefold()
        matches = [entry for entry in self._entries if entry.token.casefold() in folded]
        if not matches:
            return None
        # Prefer the longest token so specific identities win over future generic aliases.
        return max(matches, key=lambda entry: len(entry.token))

    def match(self, user_agent: str | None) -> IdentityClaim | None:
        entry = self.match_entry(user_agent)
        if entry is None:
            return None
        return IdentityClaim(
            provider=entry.provider,
            agent=entry.agent,
            actor_type=entry.actor_type,
            intent=entry.intent,
            verification_state=VerificationState.CLAIMED,
        )
