from __future__ import annotations

from datetime import UTC, datetime

from agent_traffic_intelligence.engine import Detector
from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.manager import VerificationManager
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    SourceAddressProvenance,
    VerificationEvidence,
    VerificationMethod,
    VerificationOutcome,
)
from agent_traffic_intelligence.models import (
    ActorType,
    IdentityClaim,
    RequestEvent,
    VerificationState,
)


def event() -> RequestEvent:
    return RequestEvent(
        timestamp=datetime(2026, 8, 14, 8, 0, tzinfo=UTC),
        request_id="req-v1",
        client_id="client-1",
        method="GET",
        path="/docs",
        status=200,
        bytes_sent=100,
        http_version="HTTP/2",
        user_agent="GPTBot/1.2",
        source="test",
    )


def context() -> VerificationContext:
    return VerificationContext(
        source_ip="192.0.2.10",
        source_address_provenance=SourceAddressProvenance.DIRECT_PEER,
        authority="example.com",
        method="GET",
        target_uri="https://example.com/docs",
        signature=None,
        signature_input=None,
        signature_agent=None,
        covered_headers={},
    )


class AgentPassVerifier:
    name = "agent-pass"
    method = VerificationMethod.OFFICIAL_RANGE
    binding_scope = BindingScope.AGENT

    def verify(
        self,
        *,
        event: RequestEvent,
        context: VerificationContext,
        claim: IdentityClaim,
    ) -> VerificationEvidence:
        return VerificationEvidence(
            method=self.method,
            outcome=VerificationOutcome.PASS,
            binding_scope=self.binding_scope,
            authority=claim.provider,
            subject=claim.agent,
            explanation="agent verified",
            source_uri="https://example.com/ranges.json",
            source_profile="test",
            retrieved_at=None,
            expires_at=None,
            source_sha256=None,
            details={},
        )


def test_default_detector_output_shape_remains_v0() -> None:
    detection = Detector().detect(event())
    payload = detection.to_dict()
    assert "verification" not in payload
    assert detection.verification is None
    assert detection.identity is not None
    assert detection.identity.verification_state is VerificationState.CLAIMED


def test_verification_updates_identity_state_and_confidence_only() -> None:
    base = Detector().detect(event())
    manager = VerificationManager((AgentPassVerifier(),))
    verified = Detector(verification_manager=manager).detect(
        event(), verification_context=context()
    )

    assert verified.verification is not None
    assert verified.verification.state is VerificationState.VERIFIED
    assert verified.identity is not None
    assert verified.identity.verification_state is VerificationState.VERIFIED
    assert verified.identity_confidence > base.identity_confidence
    assert verified.automation_score == base.automation_score
    assert verified.ai_score == base.ai_score
    assert verified.risk_score == base.risk_score
    assert verified.to_dict()["verification"]["schema_version"] == 1


def test_manager_without_context_preserves_v0_path() -> None:
    manager = VerificationManager((AgentPassVerifier(),))
    detection = Detector(verification_manager=manager).detect(event())
    assert detection.verification is None
    assert "verification" not in detection.to_dict()
