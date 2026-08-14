from __future__ import annotations

import pytest

from agent_traffic_intelligence.identity.sources.trust import (
    SourceTrustPolicy,
    canonicalize_source_uri,
)


def test_registry_only_policy_accepts_curated_source() -> None:
    policy = SourceTrustPolicy.default()
    assert policy.allows("https://openai.com/searchbot.json")
    assert policy.allows("https://www.perplexity.ai/perplexitybot.json")


def test_registry_only_policy_rejects_unknown_and_invalid_sources() -> None:
    policy = SourceTrustPolicy.default()
    assert not policy.allows(
        "https://attacker.example/.well-known/http-message-signatures-directory"
    )
    assert not policy.allows("http://openai.com/searchbot.json")


def test_canonicalizer_normalizes_host_default_port_and_empty_path() -> None:
    assert canonicalize_source_uri("https://EXAMPLE.com:443") == "https://example.com/"
    assert canonicalize_source_uri("https://EXAMPLE.com:8443/data?x=1#ignored") == (
        "https://example.com:8443/data?x=1"
    )


def test_canonicalizer_rejects_credentials_non_https_and_missing_host() -> None:
    with pytest.raises(ValueError, match="https"):
        canonicalize_source_uri("http://example.com/data.json")
    with pytest.raises(ValueError, match="credentials"):
        canonicalize_source_uri("https://user:pass@example.com/data.json")
    with pytest.raises(ValueError, match="hostname"):
        canonicalize_source_uri("https:///data.json")
