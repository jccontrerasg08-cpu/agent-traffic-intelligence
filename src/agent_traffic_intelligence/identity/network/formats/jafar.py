"""Parser for draft-illyes-webbotauth-jafar-00."""

from __future__ import annotations

from typing import Any

from agent_traffic_intelligence.identity.network.ranges import (
    PublishedRange,
    PublishedRangeSet,
    RangeFormatError,
    coerce_mapping,
    parse_creation_time,
    parse_network,
)


def _services(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RangeFormatError("services must be an array of strings")
    return tuple(value)


def parse_jafar(payload: bytes | str | dict[str, Any]) -> PublishedRangeSet:
    """Parse JAFAR-00 while honoring its forward-compatible ignore rules."""

    document = coerce_mapping(payload)
    creation_time = parse_creation_time(document.get("creationTime"), require_z=True)
    prefixes = document.get("prefixes")
    if not isinstance(prefixes, list):
        raise RangeFormatError("prefixes must be an array")

    sync_token = document.get("synctoken")
    if sync_token is not None and not isinstance(sync_token, str):
        raise RangeFormatError("synctoken must be a string when present")

    ranges: list[PublishedRange] = []
    for item in prefixes:
        if not isinstance(item, dict):
            continue
        has_v4 = "ipv4Prefix" in item
        has_v6 = "ipv6Prefix" in item
        if has_v4 == has_v6:
            continue
        services = _services(item.get("services"))
        if has_v4:
            network = parse_network(item["ipv4Prefix"], version=4)
        else:
            network = parse_network(item["ipv6Prefix"], version=6)
        ranges.append(PublishedRange(network=network, services=services))

    return PublishedRangeSet(
        creation_time=creation_time,
        ranges=tuple(ranges),
        source_profile="jafar-00",
        sync_token=sync_token,
    )
