from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent_traffic_intelligence.identity.network.formats.jafar import parse_jafar
from agent_traffic_intelligence.identity.network.formats.prefixes_v1 import (
    parse_prefixes_v1,
)
from agent_traffic_intelligence.identity.network.ranges import RangeFormatError


def test_prefixes_v1_parses_ipv4_and_ipv6() -> None:
    parsed = parse_prefixes_v1(
        {
            "creationTime": "2026-08-14T10:00:00Z",
            "prefixes": [
                {"ipv4Prefix": "192.0.2.0/24"},
                {"ipv6Prefix": "2001:db8::/32"},
            ],
        }
    )
    assert parsed.creation_time == datetime(2026, 8, 14, 10, 0, tzinfo=UTC)
    assert [str(item.network) for item in parsed.ranges] == [
        "192.0.2.0/24",
        "2001:db8::/32",
    ]
    assert parsed.source_profile == "prefixes-v1"


def test_prefixes_v1_rejects_malformed_prefix_object() -> None:
    with pytest.raises(RangeFormatError, match="exactly one"):
        parse_prefixes_v1(
            {
                "creationTime": "2026-08-14T10:00:00Z",
                "prefixes": [
                    {
                        "ipv4Prefix": "192.0.2.0/24",
                        "ipv6Prefix": "2001:db8::/32",
                    }
                ],
            }
        )


def test_prefixes_v1_treats_provider_naive_creation_time_as_utc() -> None:
    parsed = parse_prefixes_v1(
        {"creationTime": "2026-08-14T10:00:00.000000", "prefixes": []}
    )
    assert parsed.creation_time == datetime(2026, 8, 14, 10, 0, tzinfo=UTC)


def test_jafar_ignores_unknown_fields_and_invalid_prefix_objects() -> None:
    parsed = parse_jafar(
        {
            "creationTime": "2026-08-14T10:00:00Z",
            "synctoken": "v7",
            "futureTopLevelField": {"safe": True},
            "prefixes": [
                {
                    "ipv4Prefix": "192.0.2.0/24",
                    "services": ["crawler", "search"],
                    "futurePrefixField": 123,
                },
                {"ipv4Prefix": "198.51.100.0/24", "ipv6Prefix": "2001:db8::/32"},
                {"services": ["invalid-without-prefix"]},
            ],
        }
    )
    assert parsed.sync_token == "v7"
    assert len(parsed.ranges) == 1
    assert str(parsed.ranges[0].network) == "192.0.2.0/24"
    assert parsed.ranges[0].services == ("crawler", "search")


def test_jafar_rejects_non_string_service() -> None:
    with pytest.raises(RangeFormatError, match="services"):
        parse_jafar(
            {
                "creationTime": "2026-08-14T10:00:00Z",
                "prefixes": [
                    {"ipv4Prefix": "192.0.2.0/24", "services": ["ok", 3]}
                ],
            }
        )
