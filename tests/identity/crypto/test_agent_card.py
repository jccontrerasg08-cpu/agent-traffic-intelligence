from __future__ import annotations

import pytest

from agent_traffic_intelligence.identity.crypto.agent_card import (
    AgentCardFormatError,
    parse_agent_card,
)
from agent_traffic_intelligence.identity.standards import DEFAULT_STANDARDS_PROFILE


def test_registry_02_reads_flat_parameters_and_ignores_unknowns() -> None:
    card = parse_agent_card(
        {
            "client_name": "Example Bot",
            "expected-user-agent": "ExampleBot/2.0",
            "rfc9309-product-token": "ExampleBot",
            "rfc9309-compliance": ["User-Agent", "Disallow"],
            "trigger": "fetcher",
            "purpose": "tdm",
            "targeted-content": "public documentation",
            "rate-control": "429",
            "rate-expectation": "avg=10rps;max=100rps",
            "known-urls": ["/", "/robots.txt"],
            "ips_uri": "https://example.com/ips.json",
            "future-parameter": {"ignored": True},
        }
    )

    assert card.expected_user_agent == "ExampleBot/2.0"
    assert card.robots_product_token == "ExampleBot"
    assert card.robots_compliance == ("User-Agent", "Disallow")
    assert card.trigger == "fetcher"
    assert card.purpose == "tdm"
    assert card.targeted_content == "public documentation"
    assert card.rate_control == "429"
    assert card.rate_expectation == "avg=10rps;max=100rps"
    assert card.known_urls == ("/", "/robots.txt")
    assert card.ips_uri == "https://example.com/ips.json"


def test_registry_02_is_the_pinned_agent_card_profile() -> None:
    card = parse_agent_card({"client_name": "Example Bot"})

    assert DEFAULT_STANDARDS_PROFILE.agent_card == "draft-meunier-webbotauth-registry-02"
    assert card.profile == DEFAULT_STANDARDS_PROFILE.agent_card


def test_registry_02_retrieval_does_not_require_client_id() -> None:
    card = parse_agent_card(
        {"client_name": "Example Bot"},
        retrieved_from="https://registry.example/cards/example-bot.json",
    )

    assert card.client_name == "Example Bot"


def test_registry_02_rejects_unknown_only_card() -> None:
    with pytest.raises(AgentCardFormatError, match="recognized parameter"):
        parse_agent_card({"future-parameter": "ignored"})


def test_registry_02_rejects_invalid_trigger() -> None:
    with pytest.raises(AgentCardFormatError, match="fetcher or crawler"):
        parse_agent_card({"trigger": "interactive"})


def test_registry_02_rejects_non_https_key_and_ip_sources() -> None:
    with pytest.raises(AgentCardFormatError, match="HTTPS"):
        parse_agent_card({"jwks_uri": "http://example.com/keys"})
    with pytest.raises(AgentCardFormatError, match="HTTPS"):
        parse_agent_card({"ips_uri": "http://example.com/ips"})
