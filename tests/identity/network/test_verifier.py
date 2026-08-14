from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    SourceAddressProvenance,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.network.verifier import OfficialRangeVerifier
from agent_traffic_intelligence.identity.profiles import provider_profile
from agent_traffic_intelligence.identity.sources.models import (
    SourceDocument,
    SourceType,
)
from agent_traffic_intelligence.models import ActorType, IdentityClaim

FIXTURES = Path(__file__).parents[2] / "fixtures" / "identity" / "providers"


def claim(provider: str, agent: str) -> IdentityClaim:
    return IdentityClaim(
        provider=provider,
        agent=agent,
        actor_type=ActorType.AI_CRAWLER,
        intent="test",
    )


def context(
    address: str | None,
    provenance: SourceAddressProvenance,
) -> VerificationContext:
    return VerificationContext(
        source_ip=address,
        source_address_provenance=provenance,
        authority="example.com",
        method="GET",
        target_uri="https://example.com/",
        signature=None,
        signature_input=None,
        signature_agent=None,
        covered_headers={},
    )


def document(
    filename: str,
    provider: str,
    uri: str,
    scope: BindingScope,
) -> SourceDocument:
    body = (FIXTURES / filename).read_bytes()
    return SourceDocument.from_bytes(
        uri=uri,
        source_type=SourceType.IP_RANGES,
        provider=provider,
        binding_scope=scope,
        retrieved_at=datetime(2026, 8, 14, 11, 0, tzinfo=UTC),
        content=body,
        content_type="application/json",
        parser_profile="prefixes-v1",
    )


def test_anthropic_shared_range_pass_is_provider_scope() -> None:
    profile = provider_profile("anthropic").range_sources[0]
    evidence = OfficialRangeVerifier().verify(
        context=context("2001:db8::42", SourceAddressProvenance.DIRECT_PEER),
        claim=claim("anthropic", "ClaudeBot"),
        source_profile=profile,
        document=document(
            "anthropic-bots.json",
            "anthropic",
            profile.uri,
            profile.binding_scope,
        ),
    )
    assert evidence.outcome is VerificationOutcome.PASS
    assert evidence.binding_scope is BindingScope.PROVIDER
    assert evidence.subject == "anthropic"
    assert "2001:db8::42" not in json.dumps(evidence.to_dict())


def test_positive_only_miss_is_indeterminate() -> None:
    profile = provider_profile("anthropic").range_sources[0]
    evidence = OfficialRangeVerifier().verify(
        context=context("2001:db9::1", SourceAddressProvenance.DIRECT_PEER),
        claim=claim("anthropic", "ClaudeBot"),
        source_profile=profile,
        document=document(
            "anthropic-bots.json",
            "anthropic",
            profile.uri,
            profile.binding_scope,
        ),
    )
    assert evidence.outcome is VerificationOutcome.INDETERMINATE


def test_agent_specific_range_can_bind_exact_agent() -> None:
    profile = provider_profile("perplexity").range_sources[1]
    evidence = OfficialRangeVerifier().verify(
        context=context(
            "203.0.113.9",
            SourceAddressProvenance.TRUSTED_EDGE_CLIENT,
        ),
        claim=claim("perplexity", "Perplexity-User"),
        source_profile=profile,
        document=document(
            "perplexity-user.json",
            "perplexity",
            profile.uri,
            profile.binding_scope,
        ),
    )
    assert evidence.outcome is VerificationOutcome.PASS
    assert evidence.binding_scope is BindingScope.AGENT
    assert evidence.subject == "Perplexity-User"


def test_authoritative_negative_miss_is_mismatch() -> None:
    profile = provider_profile("perplexity").range_sources[1]
    evidence = OfficialRangeVerifier().verify(
        context=context("198.51.100.7", SourceAddressProvenance.DIRECT_PEER),
        claim=claim("perplexity", "Perplexity-User"),
        source_profile=profile,
        document=document(
            "perplexity-user.json",
            "perplexity",
            profile.uri,
            profile.binding_scope,
        ),
    )
    assert evidence.outcome is VerificationOutcome.MISMATCH


def test_untrusted_address_provenance_is_unavailable() -> None:
    profile = provider_profile("openai").range_sources[0]
    evidence = OfficialRangeVerifier().verify(
        context=context(
            "192.0.2.10",
            SourceAddressProvenance.FORWARDED_UNTRUSTED,
        ),
        claim=claim("openai", "GPTBot"),
        source_profile=profile,
        document=document(
            "openai-gptbot.json",
            "openai",
            profile.uri,
            profile.binding_scope,
        ),
    )
    assert evidence.outcome is VerificationOutcome.UNAVAILABLE
