from __future__ import annotations

import base64

import pytest

from agent_traffic_intelligence.identity.crypto.agent_card import (
    AgentCardFormatError,
    parse_agent_card,
)
from agent_traffic_intelligence.identity.standards import DEFAULT_STANDARDS_PROFILE


def inline_jwks() -> dict[str, object]:
    x = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode("ascii")
    return {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": x}]}


def test_registry_03_parses_cimd_and_web_bot_auth_extension() -> None:
    card = parse_agent_card(
        {
            "client_id": "https://example.com/bot",
            "client_name": "Example Bot",
            "jwks_uri": "https://example.com/.well-known/http-message-signatures-directory",
            "web_bot_auth": {
                "expected-user-agent": "ExampleBot/1.0",
                "trigger": "fetcher",
                "purpose": "tdm",
                "known-urls": ["/", "/robots.txt"],
                "ips_uri": "https://example.com/ips.json",
                "future-member": "ignored",
            },
        },
        retrieved_from="https://example.com/bot",
    )
    assert card.client_name == "Example Bot"
    assert card.trigger == "fetcher"
    assert card.known_urls == ("/", "/robots.txt")
    assert card.profile.endswith("-03")


def test_card_rejects_ambiguous_keys_and_bad_binding() -> None:
    with pytest.raises(AgentCardFormatError, match="both jwks_uri and jwks"):
        parse_agent_card(
            {"jwks_uri": "https://example.com/keys", "jwks": inline_jwks()}
        )
    with pytest.raises(AgentCardFormatError, match="exactly match"):
        parse_agent_card(
            {"client_id": "https://example.com/bot", "client_name": "bot"},
            retrieved_from="https://example.com/other",
        )


def test_card_rejects_non_https_key_and_ip_sources() -> None:
    with pytest.raises(AgentCardFormatError, match="HTTPS"):
        parse_agent_card({"jwks_uri": "http://example.com/keys"})
    with pytest.raises(AgentCardFormatError, match="HTTPS"):
        parse_agent_card({"web_bot_auth": {"ips_uri": "http://example.com/ips"}})


def test_registry_02_reads_flat_web_bot_auth_parameters() -> None:
    card = parse_agent_card(
        {
            "client_name": "Example Bot",
            "expected-user-agent": "ExampleBot/2.0",
            "trigger": "fetcher",
            "purpose": "training",
            "known-urls": ["https://example.com/about"],
            "ips_uri": "https://example.com/ips.json",
        }
    )

    assert card.expected_user_agent == "ExampleBot/2.0"
    assert card.trigger == "fetcher"
    assert card.purpose == "training"
    assert card.known_urls == ("https://example.com/about",)
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
