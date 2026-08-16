from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from agent_traffic_intelligence.identity.configured import apply_cached_crypto_binding
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    VerificationEvidence,
    VerificationMethod,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.profiles import (
    CryptoDiscoveryType,
    CryptoInteroperabilityProfile,
    CryptoResponseBindingPolicy,
    CryptoSourceProfile,
    provider_profile,
)
from agent_traffic_intelligence.identity.sources.models import (
    KeyAuthorityBinding,
    SourceAcquisition,
    SourceDocument,
    SourceType,
)

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
DIRECTORY_URI = "https://agent.example/.well-known/http-message-signatures-directory"
KEY_ID = "thumbprint-1"
CONTENT = b'{"keys":[]}'


def profile(policy: CryptoResponseBindingPolicy) -> CryptoSourceProfile:
    return CryptoSourceProfile(
        signature_agent_uri="https://agent.example",
        directory_uri=DIRECTORY_URI,
        interoperability_profile=CryptoInteroperabilityProfile.IETF_HTTPSIG_PROTOCOL_01,
        discovery_type=CryptoDiscoveryType.DIRECTORY,
        response_binding_policy=policy,
        binding_scope=BindingScope.AGENT,
        reviewed_on="2026-08-16",
        subject="ExampleBot",
    )


def evidence() -> VerificationEvidence:
    return VerificationEvidence(
        method=VerificationMethod.WEB_BOT_AUTH,
        outcome=VerificationOutcome.PASS,
        binding_scope=BindingScope.AGENT,
        authority="example",
        subject="ExampleBot",
        explanation="verified",
        source_uri=DIRECTORY_URI,
        source_profile="test",
        retrieved_at=None,
        expires_at=None,
        source_sha256=None,
        details={"key_thumbprint": KEY_ID},
    )


def document(
    *,
    bindings: tuple[KeyAuthorityBinding, ...] = (),
) -> SourceDocument:
    return SourceDocument.from_bytes(
        uri=DIRECTORY_URI,
        source_type=SourceType.KEY_DIRECTORY,
        provider="example",
        binding_scope=BindingScope.AGENT,
        retrieved_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
        content=CONTENT,
        content_type="application/http-message-signatures-directory+json",
        parser_profile="draft-meunier-webbotauth-httpsig-directory-00",
        key_authority_bindings=bindings,
        acquisition=SourceAcquisition.DIRECT_HTTPS,
    )


def test_google_declares_deployed_compatible_response_binding_policy() -> None:
    google = provider_profile("google")
    assert google.crypto is not None
    assert (
        google.crypto.signature_agents[0].response_binding_policy
        is CryptoResponseBindingPolicy.DEPLOYED_COMPATIBLE
    )


def test_strict_current_downgrades_direct_https_without_authority_binding() -> None:
    result = apply_cached_crypto_binding(
        evidence(),
        document=document(),
        profile=profile(CryptoResponseBindingPolicy.STRICT_CURRENT),
        now=NOW,
    )

    assert result.outcome is VerificationOutcome.PASS
    assert result.binding_scope is BindingScope.KEY
    assert result.subject == KEY_ID


def test_deployed_compatible_accepts_configured_direct_https_source() -> None:
    result = apply_cached_crypto_binding(
        evidence(),
        document=document(),
        profile=profile(CryptoResponseBindingPolicy.DEPLOYED_COMPATIBLE),
        now=NOW,
    )

    assert result.binding_scope is BindingScope.AGENT
    assert result.subject == "ExampleBot"


def test_strict_current_keeps_agent_scope_with_current_authority_binding() -> None:
    body_sha256 = hashlib.sha256(CONTENT).hexdigest()
    binding = KeyAuthorityBinding(
        key_thumbprint=KEY_ID,
        authority="agent.example",
        body_sha256=body_sha256,
        verified_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
        profile="draft-meunier-webbotauth-httpsig-directory-00",
    )
    result = apply_cached_crypto_binding(
        evidence(),
        document=document(bindings=(binding,)),
        profile=profile(CryptoResponseBindingPolicy.STRICT_CURRENT),
        now=NOW,
    )

    assert result.binding_scope is BindingScope.AGENT
    assert result.subject == "ExampleBot"
