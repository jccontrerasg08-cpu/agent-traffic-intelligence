from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agent_traffic_intelligence.features.request import request_features
from agent_traffic_intelligence.features.session import SessionFeatureState
from agent_traffic_intelligence.models import RequestEvent


def event(
    second: int,
    path: str,
    *,
    status: int = 200,
    client_id: str = "client-a",
) -> RequestEvent:
    return RequestEvent(
        timestamp=datetime(2026, 8, 14, 8, 0, tzinfo=UTC) + timedelta(seconds=second),
        request_id=f"req-{client_id}-{second}-{path}",
        client_id=client_id,
        method="GET",
        path=path,
        status=status,
        bytes_sent=100,
        http_version="HTTP/2",
        user_agent="Mozilla/5.0",
    )


def test_request_features_classify_assets_and_path_depth() -> None:
    page = request_features(event(0, "/products/42"))
    asset = request_features(event(1, "/static/app.min.js"))

    assert page["path_depth"] == 2
    assert page["is_asset"] is False
    assert asset["path_depth"] == 2
    assert asset["is_asset"] is True


def test_session_features_capture_rate_regularity_and_ratios() -> None:
    state = SessionFeatureState(max_events_per_client=16, window_seconds=300)
    samples = [
        event(0, "/a"),
        event(10, "/b"),
        event(20, "/static/app.js"),
        event(30, "/missing", status=404),
    ]

    snapshot = {}
    for sample in samples:
        snapshot = state.update(sample)

    assert snapshot["session_request_count"] == 4
    assert snapshot["session_duration_seconds"] == 30.0
    assert snapshot["mean_interarrival_seconds"] == 10.0
    assert snapshot["interarrival_cv"] == 0.0
    assert snapshot["requests_per_minute"] == pytest.approx(8.0)
    assert snapshot["asset_ratio"] == 0.25
    assert snapshot["error_ratio"] == 0.25
    assert snapshot["unique_path_ratio"] == 1.0
    assert snapshot["path_entropy_bits"] == 2.0


def test_session_state_is_bounded_per_client() -> None:
    state = SessionFeatureState(max_events_per_client=3, window_seconds=300)
    for second in (0, 10, 20, 30):
        snapshot = state.update(event(second, f"/p/{second}"))

    assert snapshot["session_request_count"] == 3
    assert snapshot["session_duration_seconds"] == 20.0


def test_session_windows_clients_independently() -> None:
    state = SessionFeatureState(max_events_per_client=8, window_seconds=30)
    state.update(event(0, "/a", client_id="client-a"))
    state.update(event(10, "/b", client_id="client-b"))
    snapshot = state.update(event(40, "/c", client_id="client-a"))

    assert snapshot["session_request_count"] == 1
    assert snapshot["session_duration_seconds"] == 0.0
