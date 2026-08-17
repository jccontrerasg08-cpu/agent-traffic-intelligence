from __future__ import annotations

import json

import pytest

from agent_traffic_intelligence.models import ActorType, VerificationState
from agent_traffic_intelligence.registry import AgentRegistry


def test_known_ai_crawler_is_a_claim_not_verified_identity() -> None:
    registry = AgentRegistry.default()
    claim = registry.match("Mozilla/5.0 compatible; GPTBot/1.2; +https://openai.com/gptbot")

    assert claim is not None
    assert claim.provider == "openai"
    assert claim.agent == "GPTBot"
    assert claim.actor_type is ActorType.AI_CRAWLER
    assert claim.verification_state is VerificationState.CLAIMED


def test_user_triggered_agent_is_distinct_from_training_crawler() -> None:
    registry = AgentRegistry.default()
    claim = registry.match("Mozilla/5.0 (compatible; Claude-User; +https://www.anthropic.com)")

    assert claim is not None
    assert claim.agent == "Claude-User"
    assert claim.actor_type is ActorType.AI_USER_AGENT
    assert claim.intent == "user-triggered-fetch"


def test_current_google_agent_is_recognized() -> None:
    registry = AgentRegistry.default()
    claim = registry.match(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko; compatible; Google-Agent; +https://developers.google.com/)"
    )

    assert claim is not None
    assert claim.provider == "google"
    assert claim.actor_type is ActorType.AI_USER_AGENT


def test_google_extended_is_not_misclassified_as_http_user_agent() -> None:
    registry = AgentRegistry.default()
    assert registry.match("Google-Extended") is None


def test_unknown_user_agent_remains_unknown() -> None:
    registry = AgentRegistry.default()
    assert registry.match("MyPrivateCrawler/0.1") is None


def _registry_entry(**overrides: object) -> dict[str, object]:
    return {
        "token": "GPTBot",
        "provider": "openai",
        "agent": "GPTBot",
        "actor_type": "ai-crawler",
        "intent": "training-crawl",
        "ai_related": True,
        "official_source": "https://example.com/agent",
        "last_verified": "2026-08-14",
        **overrides,
    }


def test_registry_rejects_empty_tokens_and_non_boolean_metadata(tmp_path) -> None:
    for entry in (
        _registry_entry(token=""),
        _registry_entry(ai_related="false"),
        _registry_entry(deprecated="false"),
    ):
        path = tmp_path / "agents.json"
        path.write_text(json.dumps({"schema_version": 1, "entries": [entry]}), encoding="utf-8")
        with pytest.raises(ValueError):
            AgentRegistry.from_path(path)


def test_registry_rejects_non_object_entries(tmp_path) -> None:
    path = tmp_path / "agents.json"
    path.write_text(
        json.dumps({"schema_version": 1, "entries": [None]}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="objects"):
        AgentRegistry.from_path(path)


def test_registry_does_not_match_embedded_agent_tokens() -> None:
    registry = AgentRegistry.default()

    assert registry.match("NotGPTBot/1.0") is None
    assert registry.match("x-GPTBot/1.0") is None
    assert registry.match("xGPTBotx/1.0") is None
    assert registry.match("GPTBot/1.0") is not None


def test_registry_sources_are_auditable() -> None:
    registry = AgentRegistry.default()
    entries = registry.entries

    assert entries
    assert all(entry.official_source.startswith("https://") for entry in entries)
    assert all(entry.last_verified == "2026-08-14" for entry in entries)
