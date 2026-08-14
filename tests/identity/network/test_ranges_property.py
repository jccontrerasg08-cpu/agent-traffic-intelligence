from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address, ip_network

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given  # type: ignore[import-not-found]  # noqa: E402
from hypothesis import strategies as st  # type: ignore[import-not-found]  # noqa: E402

from agent_traffic_intelligence.identity.network.ranges import (  # noqa: E402
    PublishedRange,
    PublishedRangeSet,
)


@given(st.integers(min_value=0, max_value=255))
def test_any_address_inside_test_network_matches(last_octet: int) -> None:
    network = ip_network("192.0.2.0/24")
    address = ip_address(int(network.network_address) + last_octet)
    published = PublishedRangeSet(
        creation_time=datetime(2026, 8, 14, tzinfo=UTC),
        ranges=(PublishedRange(network),),
        source_profile="property-test",
    )
    assert published.match(str(address)).matched is True
