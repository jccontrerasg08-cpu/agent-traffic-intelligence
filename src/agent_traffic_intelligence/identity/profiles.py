"""Data-driven provider identity verification profiles."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from importlib.resources import files
from typing import Any

from agent_traffic_intelligence.identity.models import BindingScope


class NegativeSemantics(StrEnum):
    """Meaning of a miss against a published identity source."""

    AUTHORITATIVE_NEGATIVE = "authoritative_negative"
    POSITIVE_ONLY = "positive_only"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RangeSourceProfile:
    uri: str
    format_profile: str
    binding_scope: BindingScope
    negative_semantics: NegativeSemantics
    reviewed_on: str
    subject: str | None = None
    category: str | None = None


@dataclass(frozen=True, slots=True)
class FcrdnsProfile:
    allowed_suffixes: tuple[str, ...]
    binding_scope: BindingScope
    reviewed_on: str


@dataclass(frozen=True, slots=True)
class CryptoProfile:
    signature_agents: tuple[str, ...]
    reviewed_on: str


@dataclass(frozen=True, slots=True)
class ProviderProfile:
    provider: str
    range_sources: tuple[RangeSourceProfile, ...]
    fcrdns: FcrdnsProfile | None
    crypto: CryptoProfile | None


def _required_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _parse_range_source(raw: dict[str, Any]) -> RangeSourceProfile:
    return RangeSourceProfile(
        uri=_required_string(raw.get("uri"), "range source uri"),
        format_profile=_required_string(raw.get("format_profile"), "format_profile"),
        binding_scope=BindingScope(_required_string(raw.get("binding_scope"), "binding_scope")),
        negative_semantics=NegativeSemantics(
            _required_string(raw.get("negative_semantics"), "negative_semantics")
        ),
        reviewed_on=_required_string(raw.get("reviewed_on"), "reviewed_on"),
        subject=raw.get("subject") if isinstance(raw.get("subject"), str) else None,
        category=raw.get("category") if isinstance(raw.get("category"), str) else None,
    )


def _parse_fcrdns(raw: Any) -> FcrdnsProfile | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("fcrdns profile must be an object or null")
    suffixes_raw = raw.get("allowed_suffixes")
    if not isinstance(suffixes_raw, list) or not suffixes_raw:
        raise ValueError("fcrdns allowed_suffixes must be a non-empty list")
    suffixes = tuple(
        _required_string(item, "fcrdns suffix").casefold().rstrip(".")
        for item in suffixes_raw
    )
    return FcrdnsProfile(
        allowed_suffixes=suffixes,
        binding_scope=BindingScope(
            _required_string(raw.get("binding_scope"), "fcrdns binding_scope")
        ),
        reviewed_on=_required_string(raw.get("reviewed_on"), "fcrdns reviewed_on"),
    )


def _parse_crypto(raw: Any) -> CryptoProfile | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("crypto profile must be an object or null")
    agents_raw = raw.get("signature_agents", [])
    if not isinstance(agents_raw, list):
        raise ValueError("signature_agents must be a list")
    return CryptoProfile(
        signature_agents=tuple(_required_string(item, "signature_agent") for item in agents_raw),
        reviewed_on=_required_string(raw.get("reviewed_on"), "crypto reviewed_on"),
    )


@lru_cache(maxsize=1)
def load_provider_profiles() -> dict[str, ProviderProfile]:
    """Load and validate the packaged provider verification profile registry."""

    resource = files("agent_traffic_intelligence.identity").joinpath(
        "verification_profiles.json"
    )
    payload = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("unsupported verification profile schema")
    providers_raw = payload.get("providers")
    if not isinstance(providers_raw, list):
        raise ValueError("verification profiles must contain a providers list")

    result: dict[str, ProviderProfile] = {}
    for raw in providers_raw:
        if not isinstance(raw, dict):
            raise ValueError("provider profile must be an object")
        provider = _required_string(raw.get("provider"), "provider").casefold()
        if provider in result:
            raise ValueError(f"duplicate provider profile: {provider}")
        range_sources_raw = raw.get("range_sources", [])
        if not isinstance(range_sources_raw, list):
            raise ValueError("range_sources must be a list")
        result[provider] = ProviderProfile(
            provider=provider,
            range_sources=tuple(
                _parse_range_source(item)
                for item in range_sources_raw
                if isinstance(item, dict)
            ),
            fcrdns=_parse_fcrdns(raw.get("fcrdns")),
            crypto=_parse_crypto(raw.get("crypto")),
        )
    return result


def provider_profile(provider: str) -> ProviderProfile:
    """Return a provider profile or raise a useful error."""

    key = provider.casefold()
    try:
        return load_provider_profiles()[key]
    except KeyError as exc:
        raise KeyError(f"unknown provider verification profile: {provider}") from exc
