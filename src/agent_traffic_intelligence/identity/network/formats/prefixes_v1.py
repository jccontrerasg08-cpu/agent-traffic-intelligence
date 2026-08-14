"""Parser for current provider publications using creationTime + prefixes."""

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


def parse_prefixes_v1(
    payload: bytes | str | dict[str, Any],
) -> PublishedRangeSet:
    """Parse the legacy/provider `prefixes` shape with strict drift detection."""

    document = coerce_mapping(payload)
    creation_time = parse_creation_time(document.get("creationTime"), require_z=False)
    prefixes = document.get("prefixes")
    if not isinstance(prefixes, list):
        raise RangeFormatError("prefixes must be an array")

    ranges: list[PublishedRange] = []
    for item in prefixes:
        if not isinstance(item, dict):
            raise RangeFormatError("each prefix entry must be an object")
        has_v4 = "ipv4Prefix" in item
        has_v6 = "ipv6Prefix" in item
        if has_v4 == has_v6:
            raise RangeFormatError("prefix object must contain exactly one IP prefix field")
        if has_v4:
            network = parse_network(item["ipv4Prefix"], version=4)
        else:
            network = parse_network(item["ipv6Prefix"], version=6)
        ranges.append(PublishedRange(network=network))

    return PublishedRangeSet(
        creation_time=creation_time,
        ranges=tuple(ranges),
        source_profile="prefixes-v1",
    )
