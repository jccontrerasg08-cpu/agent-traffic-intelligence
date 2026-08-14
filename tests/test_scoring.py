from __future__ import annotations

from datetime import UTC, datetime, timedelta

from agent_traffic_intelligence.engine import Detector
from agent_traffic_intelligence.models import RequestEvent


def event(
    second: int,
    *,
    ua: str | None = "Mozilla/5.0",
    path: str = "/page",
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
        user_agent=ua,
        has_referer=False,
        has_cookie=False,
        has_accept_language=True,
    )


def test_known_ai_user_agent_sets_high_automation_and_ai_but_low_identity_confidence() -> None:
    detector = Detector()
    detection = detector.detect(event(0, ua="Mozilla/5.0 compatible; GPTBot/1.0"))

    assert detection.automation_score > 0.8
    assert detection.ai_score > 0.8
    assert detection.identity_confidence < 0.2
    assert detection.risk_score < 0.5
    assert detection.identity is not None
    assert detection.identity.provider == "openai"
    assert any(item.code == "known-agent-ua-claim" for item in detection.evidence)


def test_non_ai_service_crawler_does_not_get_ai_score_just_for_provider() -> None:
    detector = Detector()
    detection = detector.detect(event(0, ua="OAI-AdsBot/1.0"))

    assert detection.automation_score > 0.8
    assert detection.ai_score < 0.3
    assert detection.identity is not None
    assert detection.identity.intent == "ad-landing-page-validation"


def test_regular_assetless_behavior_can_raise_automation_without_ai() -> None:
    detector = Detector()
    detection = None
    for second in (0, 10, 20, 30, 40, 50):
        detection = detector.detect(event(second, path=f"/article/{second}"))

    assert detection is not None
    assert detection.automation_score > 0.45
    assert detection.ai_score < 0.2
    assert detection.identity is None
    assert any(item.code == "regular-request-cadence" for item in detection.evidence)
    assert any(item.code == "html-heavy-session" for item in detection.evidence)


def test_error_probing_increases_risk_independently() -> None:
    detector = Detector()
    detection = None
    for second in (0, 2, 4, 6, 8, 10):
        detection = detector.detect(event(second, path=f"/admin/{second}", status=404))

    assert detection is not None
    assert detection.risk_score > 0.5
    assert detection.ai_score < 0.2
    assert any(item.code == "high-error-ratio" for item in detection.evidence)


def test_normal_single_browser_request_stays_low_confidence() -> None:
    detector = Detector()
    detection = detector.detect(event(0))

    assert detection.automation_score < 0.3
    assert detection.ai_score < 0.2
    assert detection.identity_confidence < 0.1
    assert detection.risk_score < 0.2
