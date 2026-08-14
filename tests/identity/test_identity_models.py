from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    SourceAddressProvenance,
    VerificationEvidence,
    VerificationMethod,
    VerificationOutcome,
    VerificationResolution,
)
from agent_traffic_intelligence.identity.policy import (
    DiscoveryPolicy,
    VerificationMode,
    VerificationPolicy,
)
from agent_traffic_intelligence.models import VerificationState


def test_context_is_ephemeral_and_has_no_serializer() -> None:
    context = VerificationContext(
        source_ip="203.0.113.10",
        source_address_provenance=SourceAddressProvenance.DIRECT_PEER,
        authority="example.com",
        method="GET",
        target_uri="https://example.com/docs",
        signature=None,
        signature_input=None,
        signature_agent=None,
        covered_headers={},
    )

    assert context.source_ip == "203.0.113.10"
    assert not hasattr(context, "to_dict")


def test_evidence_has_explicit_binding_scope_and_privacy_safe_serialization() -> None:
    evidence = VerificationEvidence(
        method=VerificationMethod.OFFICIAL_RANGE,
        outcome=VerificationOutcome.PASS,
        binding_scope=BindingScope.PROVIDER,
        authority="anthropic",
        subject="anthropic",
        explanation="matched an official provider range",
        source_uri="https://claude.com/crawling/bots.json",
        source_profile="prefixes-v1",
        retrieved_at=datetime(2026, 8, 14, tzinfo=UTC),
        expires_at=None,
        source_sha256="a" * 64,
        details={"matched_prefix_length": 20},
    )

    payload = evidence.to_dict()
    assert payload["method"] == "official_range"
    assert payload["binding_scope"] == "provider"
    assert payload["retrieved_at"] == "2026-08-14T00:00:00+00:00"
    assert "203.0.113.10" not in str(payload)


def test_evidence_rejects_naive_provenance_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        VerificationEvidence(
            method=VerificationMethod.OFFICIAL_RANGE,
            outcome=VerificationOutcome.PASS,
            binding_scope=BindingScope.PROVIDER,
            authority="example",
            subject="example",
            explanation="test",
            source_uri="https://example.com/ranges.json",
            source_profile="prefixes-v1",
            retrieved_at=datetime(2026, 8, 14),
            expires_at=None,
            source_sha256="a" * 64,
        )


def test_resolution_serializes_versioned_payload() -> None:
    resolution = VerificationResolution(
        state=VerificationState.CLAIMED,
        provider_verified=True,
        agent_verified=False,
        provider="anthropic",
        agent="ClaudeBot",
        methods=(),
        conflicts=(),
    )

    assert resolution.to_dict() == {
        "schema_version": 1,
        "state": "claimed",
        "provider_verified": True,
        "agent_verified": False,
        "provider": "anthropic",
        "agent": "ClaudeBot",
        "methods": [],
        "conflicts": [],
    }


def test_policy_defaults_offline_registry_only_and_bounded() -> None:
    policy = VerificationPolicy()

    assert policy.mode is VerificationMode.OFFLINE
    assert policy.discovery_policy is DiscoveryPolicy.REGISTRY_ONLY
    assert policy.allow_unknown_signature_agent_fetch is False
    assert policy.max_workers == 4
    assert policy.verifier_timeout_seconds == 2.0


def test_verification_state_includes_conflicted() -> None:
    assert VerificationState.CONFLICTED.value == "conflicted"
