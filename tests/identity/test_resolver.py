from __future__ import annotations

from agent_traffic_intelligence.identity.models import (
    BindingScope,
    VerificationEvidence,
    VerificationMethod,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.resolver import IdentityResolver
from agent_traffic_intelligence.models import ActorType, IdentityClaim, VerificationState


def claim(provider: str = "openai", agent: str = "GPTBot") -> IdentityClaim:
    return IdentityClaim(
        provider=provider,
        agent=agent,
        actor_type=ActorType.AI_CRAWLER,
        intent="test",
    )


def evidence(
    *,
    outcome: VerificationOutcome,
    scope: BindingScope,
    authority: str = "openai",
    subject: str | None = None,
    method: VerificationMethod = VerificationMethod.OFFICIAL_RANGE,
) -> VerificationEvidence:
    return VerificationEvidence(
        method=method,
        outcome=outcome,
        binding_scope=scope,
        authority=authority,
        subject=subject,
        explanation=f"{method.value}:{outcome.value}",
        source_uri=None,
        source_profile="test",
        retrieved_at=None,
        expires_at=None,
        source_sha256=None,
        details={},
    )


def test_provider_pass_does_not_verify_exact_agent() -> None:
    resolution = IdentityResolver().resolve(
        claim(),
        (evidence(outcome=VerificationOutcome.PASS, scope=BindingScope.PROVIDER),),
    )
    assert resolution.state is VerificationState.CLAIMED
    assert resolution.provider_verified is True
    assert resolution.agent_verified is False


def test_agent_pass_matching_claim_verifies_exact_agent() -> None:
    resolution = IdentityResolver().resolve(
        claim(),
        (
            evidence(
                outcome=VerificationOutcome.PASS,
                scope=BindingScope.AGENT,
                subject="GPTBot",
            ),
        ),
    )
    assert resolution.state is VerificationState.VERIFIED
    assert resolution.provider_verified is True
    assert resolution.agent_verified is True


def test_key_pass_alone_does_not_verify_real_world_identity() -> None:
    resolution = IdentityResolver().resolve(
        claim(),
        (
            evidence(
                outcome=VerificationOutcome.PASS,
                scope=BindingScope.KEY,
                subject="thumbprint",
                method=VerificationMethod.RFC9421,
            ),
        ),
    )
    assert resolution.state is VerificationState.CLAIMED
    assert resolution.provider_verified is False
    assert resolution.agent_verified is False


def test_conflicting_agent_passes_are_conflicted() -> None:
    resolution = IdentityResolver().resolve(
        claim(),
        (
            evidence(
                outcome=VerificationOutcome.PASS,
                scope=BindingScope.AGENT,
                subject="GPTBot",
            ),
            evidence(
                outcome=VerificationOutcome.PASS,
                scope=BindingScope.AGENT,
                authority="other",
                subject="OtherBot",
                method=VerificationMethod.WEB_BOT_AUTH,
            ),
        ),
    )
    assert resolution.state is VerificationState.CONFLICTED
    assert resolution.agent_verified is False
    assert resolution.conflicts


def test_authoritative_agent_mismatch_without_pass_is_failed() -> None:
    resolution = IdentityResolver().resolve(
        claim(),
        (
            evidence(
                outcome=VerificationOutcome.MISMATCH,
                scope=BindingScope.AGENT,
                subject="GPTBot",
            ),
        ),
    )
    assert resolution.state is VerificationState.FAILED
    assert resolution.agent_verified is False


def test_agent_pass_plus_agent_mismatch_is_conflicted() -> None:
    resolution = IdentityResolver().resolve(
        claim(),
        (
            evidence(
                outcome=VerificationOutcome.PASS,
                scope=BindingScope.AGENT,
                subject="GPTBot",
                method=VerificationMethod.WEB_BOT_AUTH,
            ),
            evidence(
                outcome=VerificationOutcome.MISMATCH,
                scope=BindingScope.AGENT,
                subject="GPTBot",
                method=VerificationMethod.OFFICIAL_RANGE,
            ),
        ),
    )
    assert resolution.state is VerificationState.CONFLICTED
    assert resolution.agent_verified is False


def test_operational_failures_never_become_failed() -> None:
    items = tuple(
        evidence(outcome=outcome, scope=BindingScope.AGENT, subject="GPTBot")
        for outcome in (
            VerificationOutcome.UNAVAILABLE,
            VerificationOutcome.INDETERMINATE,
            VerificationOutcome.STALE,
            VerificationOutcome.ERROR,
        )
    )
    resolution = IdentityResolver().resolve(claim(), items)
    assert resolution.state is VerificationState.CLAIMED


def test_output_evidence_order_is_deterministic() -> None:
    unordered = (
        evidence(
            outcome=VerificationOutcome.UNAVAILABLE,
            scope=BindingScope.PROVIDER,
            method=VerificationMethod.FCRDNS,
        ),
        evidence(
            outcome=VerificationOutcome.PASS,
            scope=BindingScope.AGENT,
            subject="GPTBot",
            method=VerificationMethod.WEB_BOT_AUTH,
        ),
        evidence(
            outcome=VerificationOutcome.PASS,
            scope=BindingScope.PROVIDER,
            method=VerificationMethod.OFFICIAL_RANGE,
        ),
    )
    forward = IdentityResolver().resolve(claim(), unordered)
    backward = IdentityResolver().resolve(claim(), tuple(reversed(unordered)))
    assert forward.methods == backward.methods
    assert [item.method.value for item in forward.methods] == [
        "fcrdns",
        "official_range",
        "web_bot_auth",
    ]
