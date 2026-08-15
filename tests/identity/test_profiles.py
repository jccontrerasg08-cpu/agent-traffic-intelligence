import json

import pytest

import agent_traffic_intelligence.identity.profiles as profiles_module
from agent_traffic_intelligence.identity.models import BindingScope
from agent_traffic_intelligence.identity.profiles import (
    _required_https_uri,
    _required_iso_date,
    provider_profile,
)
from agent_traffic_intelligence.identity.standards import DEFAULT_STANDARDS_PROFILE


def test_anthropic_has_no_ip_range_source_without_official_publication() -> None:
    profile = provider_profile("anthropic")
    assert profile.range_sources == ()
    assert profile.fcrdns is None


def test_perplexity_sources_are_agent_scoped() -> None:
    profile = provider_profile("perplexity")
    subjects = {source.subject for source in profile.range_sources}
    assert subjects == {"PerplexityBot", "Perplexity-User"}
    assert all(source.binding_scope is BindingScope.AGENT for source in profile.range_sources)


def test_google_profile_keeps_documented_fcrdns_suffixes() -> None:
    profile = provider_profile("google")
    assert profile.fcrdns is not None
    documented_suffixes = {
        "googlebot.com",
        "google.com",
        "gae.googleusercontent.com",
    }
    assert documented_suffixes <= set(profile.fcrdns.allowed_suffixes)


def test_default_standards_profile_is_pinned() -> None:
    profile = DEFAULT_STANDARDS_PROFILE
    assert profile.http_message_signatures == "RFC9421"
    assert (
        profile.web_bot_auth_protocol
        == "draft-meunier-webbotauth-httpsig-protocol-01"
    )
    assert (
        profile.message_signatures_directory
        == "draft-meunier-webbotauth-httpsig-directory-00"
    )
    assert profile.jafar == "draft-illyes-webbotauth-jafar-00"
    assert profile.agent_card == "draft-meunier-webbotauth-registry-03"


def test_google_crypto_profile_separates_identity_and_directory_uri() -> None:
    profile = provider_profile("google")
    assert profile.crypto is not None
    source = profile.crypto.signature_agents[0]
    assert source.signature_agent_uri == "https://agent.bot.goog"
    assert (
        source.directory_uri
        == "https://agent.bot.goog/.well-known/http-message-signatures-directory"
    )
    assert source.binding_scope is BindingScope.AGENT
    assert source.subject == "Google-Agent"
    assert source.interoperability_profile == "ietf-httpsig-protocol-01"
    assert source.discovery_type == "directory"


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("http://example.test/ranges.json", "HTTPS"),
        ("https://user:pass@example.test/ranges.json", "credentials"),
        ("https://example.test/ranges.json#fragment", "fragment"),
    ],
)
def test_profile_uris_require_safe_absolute_https(value: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _required_https_uri(value, "source uri")


def test_profile_review_date_requires_iso_format() -> None:
    with pytest.raises(ValueError, match="ISO-8601"):
        _required_iso_date("14-08-2026", "reviewed_on")


def test_profile_loader_rejects_non_object_range_sources(monkeypatch) -> None:
    payload = {
        "schema_version": 1,
        "providers": [
            {
                "provider": "example",
                "range_sources": ["not-an-object"],
                "fcrdns": None,
                "crypto": None,
            }
        ],
    }

    class FakeResource:
        def joinpath(self, _name: str) -> "FakeResource":
            return self

        def read_text(self, *, encoding: str) -> str:
            assert encoding == "utf-8"
            return json.dumps(payload)

    monkeypatch.setattr(profiles_module, "files", lambda _package: FakeResource())
    profiles_module.load_provider_profiles.cache_clear()
    try:
        with pytest.raises(ValueError, match="range source profile"):
            profiles_module.load_provider_profiles()
    finally:
        profiles_module.load_provider_profiles.cache_clear()
