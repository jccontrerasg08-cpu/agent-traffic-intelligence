from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from agent_traffic_intelligence.identity.configured import (
    ProviderAwareVerificationManager,
    signature_agent_profile_for,
)
from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.signature_agent import SignatureAgentProfile
from agent_traffic_intelligence.identity.models import (
    SourceAddressProvenance,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.policy import VerificationMode
from agent_traffic_intelligence.identity.profiles import (
    CryptoInteroperabilityProfile,
    provider_profile,
)
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.models import SourceDocument, SourceType
from agent_traffic_intelligence.identity.standards import DEFAULT_STANDARDS_PROFILE
from agent_traffic_intelligence.models import (
    ActorType,
    IdentityClaim,
    RequestEvent,
    VerificationState,
)

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)


def event() -> RequestEvent:
    return RequestEvent(
        timestamp=NOW,
        request_id="configured-1",
        client_id="client-1",
        method="GET",
        path="/docs",
        status=200,
        bytes_sent=100,
        http_version="HTTP/2",
        user_agent="GPTBot/1.2",
        source="test",
    )


def claim() -> IdentityClaim:
    return IdentityClaim(
        provider="openai",
        agent="GPTBot",
        actor_type=ActorType.AI_CRAWLER,
        intent="training",
    )


def context() -> VerificationContext:
    return VerificationContext(
        source_ip="192.0.2.7",
        source_address_provenance=SourceAddressProvenance.DIRECT_PEER,
        authority="example.com",
        method="GET",
        target_uri="https://example.com/docs",
        signature=None,
        signature_input=None,
        signature_agent=None,
        covered_headers={},
    )


def cache_gptbot_range(
    cache: SourceCache,
    *,
    expires_at: datetime | None = None,
) -> None:
    profile = provider_profile("openai").range_sources[0]
    document = SourceDocument.from_bytes(
        uri=profile.uri,
        source_type=SourceType.IP_RANGES,
        provider="openai",
        binding_scope=profile.binding_scope,
        retrieved_at=NOW - timedelta(minutes=5),
        expires_at=expires_at,
        content=(
            b'{"creationTime":"2026-08-14T11:55:00Z",'
            b'"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}'
        ),
        content_type="application/json",
        parser_profile=profile.format_profile,
    )
    cache.put(document)


def test_only_claim_applicable_agent_range_is_executed(tmp_path) -> None:
    manager = ProviderAwareVerificationManager(SourceCache(tmp_path))
    resolution = manager.verify(event=event(), context=context(), claim=claim())

    assert resolution.state is VerificationState.CLAIMED
    assert len(resolution.methods) == 1
    assert resolution.methods[0].outcome is VerificationOutcome.UNAVAILABLE
    assert resolution.methods[0].subject == "GPTBot"


def test_cached_agent_range_verifies_exact_agent(tmp_path) -> None:
    cache = SourceCache(tmp_path)
    cache_gptbot_range(cache)
    resolution = ProviderAwareVerificationManager(cache).verify(
        event=event(),
        context=context(),
        claim=claim(),
    )

    assert resolution.state is VerificationState.VERIFIED
    assert resolution.provider_verified is True
    assert resolution.agent_verified is True
    assert resolution.methods[0].outcome is VerificationOutcome.PASS


def test_stale_cached_range_is_neutral_not_identity_failure(tmp_path) -> None:
    cache = SourceCache(tmp_path)
    cache_gptbot_range(cache, expires_at=NOW - timedelta(seconds=1))
    resolution = ProviderAwareVerificationManager(cache).verify(
        event=event(),
        context=context(),
        claim=claim(),
    )

    assert resolution.state is VerificationState.CLAIMED
    assert resolution.methods[0].outcome is VerificationOutcome.STALE


def test_offline_mode_does_not_add_fcrdns_verifier(tmp_path) -> None:
    google_claim = IdentityClaim(
        provider="google",
        agent="Googlebot",
        actor_type=ActorType.SEARCH_CRAWLER,
        intent="search-indexing",
    )
    resolution = ProviderAwareVerificationManager(
        SourceCache(tmp_path),
        mode=VerificationMode.OFFLINE,
    ).verify(event=event(), context=context(), claim=google_claim)

    assert all(item.method.value != "fcrdns" for item in resolution.methods)


def test_runtime_maps_declarative_signature_agent_profile() -> None:
    google = provider_profile("google")
    assert google.crypto is not None
    source = google.crypto.signature_agents[0]

    assert (
        signature_agent_profile_for(source)
        is SignatureAgentProfile.IETF_HTTPSIG_PROTOCOL_01
    )

    legacy = replace(
        source,
        interoperability_profile=CryptoInteroperabilityProfile.CLOUDFLARE_LEGACY,
    )
    assert signature_agent_profile_for(legacy) is SignatureAgentProfile.CLOUDFLARE_LEGACY


def test_malformed_cached_directory_error_reports_current_profile(tmp_path) -> None:
    google = provider_profile("google")
    assert google.crypto is not None
    source = google.crypto.signature_agents[0]
    cache = SourceCache(tmp_path)
    cache.put(
        SourceDocument.from_bytes(
            uri=source.directory_uri,
            source_type=SourceType.KEY_DIRECTORY,
            provider="google",
            binding_scope=source.binding_scope,
            retrieved_at=NOW,
            content=b"{}",
            content_type="application/http-message-signatures-directory+json",
            parser_profile=DEFAULT_STANDARDS_PROFILE.message_signatures_directory,
        )
    )
    signed_context = replace(
        context(),
        signature="sig1=:placeholder:",
        signature_input='sig1=("@authority");created=1',
    )
    google_claim = IdentityClaim(
        provider="google",
        agent="Google-Agent",
        actor_type=ActorType.AI_CRAWLER,
        intent="user-triggered",
    )

    resolution = ProviderAwareVerificationManager(cache).verify(
        event=event(),
        context=signed_context,
        claim=google_claim,
    )
    evidence = next(
        item for item in resolution.methods if item.outcome is VerificationOutcome.ERROR
    )

    assert evidence.source_profile == DEFAULT_STANDARDS_PROFILE.message_signatures_directory
