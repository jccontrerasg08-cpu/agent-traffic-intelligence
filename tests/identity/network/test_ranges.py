from __future__ import annotations

import json
from datetime import UTC, datetime
from ipaddress import ip_network

from agent_traffic_intelligence.identity.network.ranges import (
    PublishedRange,
    PublishedRangeSet,
)


def range_set(*ranges: PublishedRange) -> PublishedRangeSet:
    return PublishedRangeSet(
        creation_time=datetime(2026, 8, 14, tzinfo=UTC),
        ranges=ranges,
        source_profile="test",
    )


def test_match_ipv4_ipv6_and_mapped_ipv4() -> None:
    published = range_set(
        PublishedRange(ip_network("192.0.2.0/24"), ("v4",)),
        PublishedRange(ip_network("2001:db8::/32"), ("v6",)),
    )

    assert published.match("192.0.2.9").services == ("v4",)
    assert published.match("2001:db8::1234").services == ("v6",)
    assert published.match("::ffff:192.0.2.9").services == ("v4",)
    assert published.match("198.51.100.1").matched is False


def test_most_specific_prefix_wins() -> None:
    published = range_set(
        PublishedRange(ip_network("192.0.2.0/24"), ("broad",)),
        PublishedRange(ip_network("192.0.2.128/25"), ("specific",)),
    )

    match = published.match("192.0.2.200")
    assert match.matched is True
    assert match.prefix_length == 25
    assert match.services == ("specific",)


def test_range_match_serialization_never_contains_queried_address() -> None:
    address = "192.0.2.42"
    match = range_set(PublishedRange(ip_network("192.0.2.0/24"))).match(address)

    serialized = json.dumps(match.to_dict())
    assert address not in serialized
    assert match.to_dict() == {
        "matched": True,
        "prefix_length": 24,
        "services": [],
    }
