"""Normalized IP-range model shared by provider source formats."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from typing import Any

Network = IPv4Network | IPv6Network
Address = IPv4Address | IPv6Address


class RangeFormatError(ValueError):
    """Raised when a published range document violates its declared profile."""


@dataclass(frozen=True, slots=True)
class PublishedRange:
    """One normalized network prefix and optional case-sensitive service names."""

    network: Network
    services: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RangeMatch:
    """Privacy-safe result of matching an address against a published range set."""

    matched: bool
    prefix_length: int | None = None
    services: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, bool | int | list[str] | None]:
        return {
            "matched": self.matched,
            "prefix_length": self.prefix_length,
            "services": list(self.services),
        }


@dataclass(frozen=True, slots=True)
class PublishedRangeSet:
    """Normalized contents of one provider IP-range publication."""

    creation_time: datetime
    ranges: tuple[PublishedRange, ...]
    source_profile: str
    sync_token: str | None = None

    def __post_init__(self) -> None:
        if self.creation_time.tzinfo is None or self.creation_time.utcoffset() is None:
            raise RangeFormatError("creationTime must be timezone-aware")
        if not self.source_profile:
            raise RangeFormatError("source_profile must not be empty")

    def match(self, raw_address: str) -> RangeMatch:
        """Return the most-specific matching prefix without retaining the address."""

        try:
            address: Address = ip_address(raw_address)
        except ValueError as exc:
            raise RangeFormatError("query address must be a valid IPv4 or IPv6 address") from exc
        if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped

        candidates = [
            item
            for item in self.ranges
            if item.network.version == address.version and address in item.network
        ]
        if not candidates:
            return RangeMatch(matched=False)
        winner = max(candidates, key=lambda item: item.network.prefixlen)
        return RangeMatch(
            matched=True,
            prefix_length=winner.network.prefixlen,
            services=winner.services,
        )


def coerce_mapping(payload: bytes | str | Mapping[str, Any]) -> Mapping[str, Any]:
    """Decode JSON bytes/text or accept an existing mapping."""

    if isinstance(payload, bytes):
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RangeFormatError("range document must be valid UTF-8 JSON") from exc
    elif isinstance(payload, str):
        try:
            value = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RangeFormatError("range document must be valid JSON") from exc
    else:
        value = payload
    if not isinstance(value, Mapping):
        raise RangeFormatError("range document must be a JSON object")
    return value


def parse_creation_time(value: Any, *, require_z: bool) -> datetime:
    """Parse source creationTime, normalizing provider-naive timestamps to UTC."""

    if not isinstance(value, str) or not value:
        raise RangeFormatError("creationTime must be a non-empty ISO-8601 string")
    if require_z and not value.endswith("Z"):
        raise RangeFormatError("creationTime must use the Z timezone (UTC)")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise RangeFormatError("creationTime must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        if require_z:
            raise RangeFormatError("creationTime must be timezone-aware")
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def parse_network(value: Any, *, version: int) -> Network:
    """Normalize one CIDR and require the field's declared IP version."""

    if not isinstance(value, str) or not value:
        raise RangeFormatError("prefix must be a non-empty CIDR string")
    try:
        network = ip_network(value, strict=False)
    except ValueError as exc:
        raise RangeFormatError(f"invalid CIDR prefix: {value}") from exc
    if network.version != version:
        raise RangeFormatError(f"prefix does not match declared IPv{version} field")
    return network
