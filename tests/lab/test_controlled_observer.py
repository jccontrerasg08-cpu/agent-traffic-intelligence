"""Contract tests for the local owned target used in controlled campaigns."""

from datetime import UTC, datetime

from lab.controlled_observer import build_observation_record


def test_controlled_record_is_minimized_and_marks_only_the_controlled_arm() -> None:
    """The target strips queries and preserves campaign provenance for owned traffic."""

    record = build_observation_record(
        request_uri="/products?private=discard",
        headers={
            "X-ATI-Lab-Client": "controlled",
            "X-ATI-Experiment-ID": "owned-campaign-01",
            "User-Agent": "ATI controlled client",
            "Accept-Language": "es-MX",
        },
        status=200,
        bytes_sent=2,
        observed_at=datetime(2026, 8, 19, tzinfo=UTC),
    )

    assert record["remote_addr"] == "198.51.100.10"
    assert record["request_uri"] == "/products"
    assert "private=discard" not in record.values()
    assert record["ati_campaign_id"] == "owned-campaign-01"
    assert record["has_accept_language"] is True


def test_browser_arm_is_not_marked_as_a_controlled_campaign() -> None:
    """Unmarked requests remain distinct from marker-derived ground truth."""

    record = build_observation_record(
        request_uri="/",
        headers={"X-ATI-Lab-Client": "browser"},
        status=200,
        bytes_sent=2,
    )

    assert record["remote_addr"] == "198.51.100.20"
    assert "ati_campaign_id" not in record
