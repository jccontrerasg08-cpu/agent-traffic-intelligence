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


def test_registry_only_policy_rejects_unknown_signature_agent() -> None:
    policy = SourceTrustPolicy.default()
    assert not policy.allows(
        "https://attacker.example/.well-known/http-message-signatures-directory"
    )


def test_canonicalizer_rejects_credentials_and_non_https() -> None:
    with pytest.raises(ValueError, match="https"):
        canonicalize_source_uri("http://example.com/data.json")
    with pytest.raises(ValueError, match="credentials"):
        canonicalize_source_uri("https://user:pass@example.com/data.json")
