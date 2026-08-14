from agent_traffic_intelligence.identity.models import BindingScope
from agent_traffic_intelligence.identity.profiles import (
    NegativeSemantics,
    provider_profile,
)
from agent_traffic_intelligence.identity.standards import DEFAULT_STANDARDS_PROFILE


def test_anthropic_shared_range_is_provider_scope() -> None:
    source = provider_profile("anthropic").range_sources[0]
    assert source.uri == "https://claude.com/crawling/bots.json"
    assert source.binding_scope is BindingScope.PROVIDER
    assert source.negative_semantics is NegativeSemantics.POSITIVE_ONLY


def test_perplexity_sources_are_agent_scoped() -> None:
    profile = provider_profile("perplexity")
    subjects = {source.subject for source in profile.range_sources}
    assert subjects == {"PerplexityBot", "Perplexity-User"}
    assert all(source.binding_scope is BindingScope.AGENT for source in profile.range_sources)


def test_google_profile_keeps_documented_fcrdns_suffixes() -> None:
    profile = provider_profile("google")
    assert profile.fcrdns is not None
    assert "googlebot.com" in profile.fcrdns.allowed_suffixes
    assert "google.com" in profile.fcrdns.allowed_suffixes
    assert "gae.googleusercontent.com" in profile.fcrdns.allowed_suffixes


def test_default_standards_profile_is_pinned() -> None:
    profile = DEFAULT_STANDARDS_PROFILE
    assert profile.http_message_signatures == "RFC9421"
    assert profile.web_bot_auth_architecture == "draft-meunier-web-bot-auth-architecture-05"
    assert (
        profile.message_signatures_directory
        == "draft-meunier-http-message-signatures-directory-05"
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
