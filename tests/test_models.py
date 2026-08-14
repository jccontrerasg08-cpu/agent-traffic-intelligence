from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent_traffic_intelligence.models import (
    ActorType,
    Detection,
    Evidence,
    IdentityClaim,
    RequestEvent,
    VerificationState,
)


def sample_event() -> RequestEvent:
    return RequestEvent(
        timestamp=datetime(2026, 8, 14, 8, 0, tzinfo=UTC),
        request_id="req-1",
        client_id="client-abc",
        method="GET",
        path="/docs",
        status=200,
        bytes_sent=1234,
        http_version="HTTP/2",
        user_agent="ExampleBot/1.0",
        has_referer=False,
        has_cookie=False,
        has_accept_language=True,
        ja4=None,
        source="test",
    )


def test_request_event_serializes_without_private_fields() -> None:
    payload = sample_event().to_dict()

    assert payload["timestamp"] == "2026-08-14T08:00:00+00:00"
    assert payload["path"] == "/docs"
    assert "remote_addr" not in payload
    assert "cookie" not in payload


def test_request_event_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        RequestEvent(
            timestamp=datetime(2026, 8, 14, 8, 0),
            request_id="req-1",
            client_id="client-abc",
            method="GET",
            path="/",
            status=200,
            bytes_sent=0,
            http_version="HTTP/1.1",
            user_agent=None,
        )


def test_evidence_strength_is_bounded() -> None:
    with pytest.raises(ValueError, match="strength"):
        Evidence(
            code="bad",
            source="test",
            description="out of bounds",
            strength=1.01,
            score_deltas={"automation": 1.0},
        )


def test_detection_keeps_score_dimensions_independent() -> None:
    detection = Detection(
        request_id="req-1",
        automation_score=0.97,
        ai_score=0.92,
        identity_confidence=0.08,
        risk_score=0.21,
        identity=IdentityClaim(
            provider="openai",
            agent="GPTBot",
            actor_type=ActorType.AI_CRAWLER,
            intent="model-development",
            verification_state=VerificationState.CLAIMED,
        ),
        evidence=(),
        features={"path_depth": 1.0},
        ruleset_version="2026-08-14",
    )

    payload = detection.to_dict()
    assert payload["automation_score"] == 0.97
    assert payload["ai_score"] == 0.92
    assert payload["identity_confidence"] == 0.08
    assert payload["risk_score"] == 0.21
    assert payload["identity"]["verification_state"] == "claimed"


def test_detection_rejects_scores_outside_unit_interval() -> None:
    with pytest.raises(ValueError, match="automation_score"):
        Detection(
            request_id="req-1",
            automation_score=1.2,
            ai_score=0.0,
            identity_confidence=0.0,
            risk_score=0.0,
            identity=None,
            evidence=(),
            features={},
            ruleset_version="test",
        )
