import json
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator

from agent_traffic_intelligence.identity.models import VerificationResolution
from agent_traffic_intelligence.models import (
    ActorType,
    Detection,
    Evidence,
    IdentityClaim,
    RequestEvent,
    VerificationState,
)

SCHEMA_DIR = Path(__file__).parents[1] / "schemas"


def schema(name: str) -> dict[str, object]:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def event() -> RequestEvent:
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
        source="test",
    )


def detection() -> Detection:
    return Detection(
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
        evidence=(
            Evidence(
                code="known-agent",
                source="registry",
                description="Known agent declaration.",
                strength=1.0,
                score_deltas={"automation": 2.5, "ai": 1.0},
            ),
        ),
        features={"path_depth": 1, "has_ua": True, "family": "known"},
        ruleset_version="2026-08-14",
    )


def errors(payload: dict[str, object], schema_name: str) -> list[object]:
    return list(Draft202012Validator(schema(schema_name)).iter_errors(payload))


def test_published_schemas_are_valid_draft_2020_12_documents() -> None:
    for name in (
        "request-event.schema.json",
        "detection.schema.json",
        "verification.schema.json",
    ):
        Draft202012Validator.check_schema(schema(name))


def test_request_event_output_conforms_to_the_published_schema() -> None:
    assert errors(event().to_dict(), "request-event.schema.json") == []


def test_detection_output_conforms_to_the_published_schema() -> None:
    payload = detection().to_dict()

    assert payload["schema_version"] == 1
    assert errors(payload, "detection.schema.json") == []


def test_verification_output_conforms_to_the_published_schema() -> None:
    resolution = VerificationResolution(
        state=VerificationState.CLAIMED,
        provider_verified=False,
        agent_verified=False,
        provider="openai",
        agent="GPTBot",
        methods=(),
        conflicts=(),
    )

    assert errors(resolution.to_dict(), "verification.schema.json") == []


def test_detection_schema_rejects_undeclared_properties() -> None:
    payload = detection().to_dict()
    payload["unexpected"] = "not part of the public contract"

    assert errors(payload, "detection.schema.json")
