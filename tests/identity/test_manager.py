from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Barrier

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.manager import VerificationManager
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    SourceAddressProvenance,
    VerificationEvidence,
    VerificationMethod,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.policy import VerificationPolicy
from agent_traffic_intelligence.models import ActorType, IdentityClaim, RequestEvent


def sample_event() -> RequestEvent:
    return RequestEvent(
        timestamp=datetime(2026, 8, 14, 8, 0, tzinfo=UTC),
        request_id="req-1",
        client_id="client-abc",
        method="GET",
        path="/docs",
        status=200,
        bytes_sent=1234,
        http_version="HTTP/2",
        user_agent="GPTBot/1.0",
        source="test",
    )


def claim() -> IdentityClaim:
    return IdentityClaim(
        provider="openai",
        agent="GPTBot",
        actor_type=ActorType.AI_CRAWLER,
        intent="test",
    )


def context() -> VerificationContext:
    return VerificationContext(
        source_ip="192.0.2.1",
        source_address_provenance=SourceAddressProvenance.DIRECT_PEER,
        authority="example.com",
        method="GET",
        target_uri="https://example.com/",
        signature=None,
        signature_input=None,
        signature_agent=None,
        covered_headers={},
    )


def result(method: VerificationMethod, scope: BindingScope) -> VerificationEvidence:
    return VerificationEvidence(
        method=method,
        outcome=VerificationOutcome.PASS,
        binding_scope=scope,
        authority="openai",
        subject="GPTBot" if scope is BindingScope.AGENT else "openai",
        explanation="verified",
        source_uri=None,
        source_profile="test",
        retrieved_at=None,
        expires_at=None,
        source_sha256=None,
        details={},
    )


@dataclass
class StaticVerifier:
    name: str
    method: VerificationMethod
    binding_scope: BindingScope
    value: VerificationEvidence

    def verify(
        self,
        *,
        event: RequestEvent,
        context: VerificationContext,
        claim: IdentityClaim,
    ) -> VerificationEvidence:
        return self.value


@dataclass
class BarrierVerifier:
    name: str
    method: VerificationMethod
    binding_scope: BindingScope
    barrier: Barrier

    def verify(
        self,
        *,
        event: RequestEvent,
        context: VerificationContext,
        claim: IdentityClaim,
    ) -> VerificationEvidence:
        self.barrier.wait(timeout=0.5)
        return result(self.method, self.binding_scope)


@dataclass
class SlowVerifier:
    name: str = "slow"
    method: VerificationMethod = VerificationMethod.FCRDNS
    binding_scope: BindingScope = BindingScope.PROVIDER

    def verify(
        self,
        *,
        event: RequestEvent,
        context: VerificationContext,
        claim: IdentityClaim,
    ) -> VerificationEvidence:
        time.sleep(0.2)
        return result(self.method, self.binding_scope)


@dataclass
class ExplodingVerifier:
    name: str = "explode"
    method: VerificationMethod = VerificationMethod.RFC9421
    binding_scope: BindingScope = BindingScope.KEY

    def verify(
        self,
        *,
        event: RequestEvent,
        context: VerificationContext,
        claim: IdentityClaim,
    ) -> VerificationEvidence:
        raise RuntimeError("secret internal text must not leak")


def test_independent_verifiers_overlap_in_bounded_executor() -> None:
    barrier = Barrier(2)
    manager = VerificationManager(
        (
            BarrierVerifier(
                "network", VerificationMethod.OFFICIAL_RANGE, BindingScope.PROVIDER, barrier
            ),
            BarrierVerifier(
                "crypto", VerificationMethod.WEB_BOT_AUTH, BindingScope.AGENT, barrier
            ),
        ),
        policy=VerificationPolicy(max_workers=2, verifier_timeout_seconds=1.0),
    )
    resolution = manager.verify(event=sample_event(), context=context(), claim=claim())
    assert resolution.agent_verified is True
    assert len(resolution.methods) == 2


def test_timeout_does_not_block_fast_verifier() -> None:
    fast = StaticVerifier(
        "fast",
        VerificationMethod.OFFICIAL_RANGE,
        BindingScope.AGENT,
        result(VerificationMethod.OFFICIAL_RANGE, BindingScope.AGENT),
    )
    manager = VerificationManager(
        (SlowVerifier(), fast),
        policy=VerificationPolicy(max_workers=2, verifier_timeout_seconds=0.02),
    )
    started = time.monotonic()
    resolution = manager.verify(event=sample_event(), context=context(), claim=claim())
    elapsed = time.monotonic() - started

    assert elapsed < 0.15
    assert resolution.agent_verified is True
    timeout = next(
        item for item in resolution.methods if item.method is VerificationMethod.FCRDNS
    )
    assert timeout.outcome is VerificationOutcome.UNAVAILABLE
    assert timeout.details["timeout"] is True


def test_verifier_exception_becomes_privacy_safe_error_evidence() -> None:
    manager = VerificationManager((ExplodingVerifier(),))
    resolution = manager.verify(event=sample_event(), context=context(), claim=claim())
    item = resolution.methods[0]
    assert item.outcome is VerificationOutcome.ERROR
    assert "RuntimeError" in item.explanation
    assert "secret internal" not in item.explanation


def test_completion_order_does_not_change_serialized_order() -> None:
    first = StaticVerifier(
        "z",
        VerificationMethod.WEB_BOT_AUTH,
        BindingScope.AGENT,
        result(VerificationMethod.WEB_BOT_AUTH, BindingScope.AGENT),
    )
    second = StaticVerifier(
        "a",
        VerificationMethod.OFFICIAL_RANGE,
        BindingScope.PROVIDER,
        result(VerificationMethod.OFFICIAL_RANGE, BindingScope.PROVIDER),
    )
    manager = VerificationManager((first, second))
    resolution = manager.verify(event=sample_event(), context=context(), claim=claim())
    assert [item.method.value for item in resolution.methods] == [
        "official_range",
        "web_bot_auth",
    ]
