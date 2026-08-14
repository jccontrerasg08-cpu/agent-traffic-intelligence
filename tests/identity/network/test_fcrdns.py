from __future__ import annotations

import socket

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    SourceAddressProvenance,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.network.fcrdns import FcrdnsVerifier
from agent_traffic_intelligence.identity.profiles import FcrdnsProfile, provider_profile
from agent_traffic_intelligence.models import ActorType, IdentityClaim


class FakeResolver:
    def __init__(
        self,
        *,
        reverse_result: tuple[str, ...] = (),
        forward_result: tuple[str, ...] = (),
        reverse_error: BaseException | None = None,
        forward_error: BaseException | None = None,
    ) -> None:
        self.reverse_result = reverse_result
        self.forward_result = forward_result
        self.reverse_error = reverse_error
        self.forward_error = forward_error

    def reverse(self, address: str) -> tuple[str, ...]:
        if self.reverse_error is not None:
            raise self.reverse_error
        return self.reverse_result

    def forward(self, hostname: str) -> tuple[str, ...]:
        if self.forward_error is not None:
            raise self.forward_error
        return self.forward_result


def context(address: str | None) -> VerificationContext:
    return VerificationContext(
        source_ip=address,
        source_address_provenance=SourceAddressProvenance.DIRECT_PEER,
        authority="example.com",
        method="GET",
        target_uri="https://example.com/",
        signature=None,
        signature_input=None,
        signature_agent=None,
        covered_headers={},
    )


def claim() -> IdentityClaim:
    return IdentityClaim(
        provider="google",
        agent="Googlebot",
        actor_type=ActorType.SEARCH_CRAWLER,
        intent="search-indexing",
    )


def google_policy() -> FcrdnsProfile:
    profile = provider_profile("google").fcrdns
    assert profile is not None
    return profile


def test_reverse_and_forward_confirmation_passes() -> None:
    resolver = FakeResolver(
        reverse_result=("crawl-203-0-113-7.googlebot.com.",),
        forward_result=("203.0.113.7",),
    )
    evidence = FcrdnsVerifier(resolver).verify(
        context=context("203.0.113.7"), claim=claim(), profile=google_policy()
    )

    assert evidence.outcome is VerificationOutcome.PASS
    assert evidence.binding_scope is BindingScope.PROVIDER
    assert evidence.details["confirmed"] is True
    assert "203.0.113.7" not in str(evidence.to_dict())


def test_ptr_only_spoof_with_suffix_in_middle_is_mismatch() -> None:
    resolver = FakeResolver(
        reverse_result=("crawler.googlebot.com.attacker.example",),
        forward_result=("203.0.113.7",),
    )
    evidence = FcrdnsVerifier(resolver).verify(
        context=context("203.0.113.7"), claim=claim(), profile=google_policy()
    )

    assert evidence.outcome is VerificationOutcome.MISMATCH


def test_forward_mismatch_is_mismatch() -> None:
    resolver = FakeResolver(
        reverse_result=("crawl.googlebot.com",),
        forward_result=("198.51.100.11",),
    )
    evidence = FcrdnsVerifier(resolver).verify(
        context=context("203.0.113.7"), claim=claim(), profile=google_policy()
    )

    assert evidence.outcome is VerificationOutcome.MISMATCH


def test_dns_timeout_is_unavailable() -> None:
    resolver = FakeResolver(reverse_error=TimeoutError("resolver timeout"))
    evidence = FcrdnsVerifier(resolver).verify(
        context=context("203.0.113.7"), claim=claim(), profile=google_policy()
    )

    assert evidence.outcome is VerificationOutcome.UNAVAILABLE


def test_nxdomain_is_unavailable() -> None:
    resolver = FakeResolver(reverse_error=socket.herror("not found"))
    evidence = FcrdnsVerifier(resolver).verify(
        context=context("203.0.113.7"), claim=claim(), profile=google_policy()
    )

    assert evidence.outcome is VerificationOutcome.UNAVAILABLE


def test_missing_provider_dns_policy_is_unavailable() -> None:
    evidence = FcrdnsVerifier(FakeResolver()).verify(
        context=context("203.0.113.7"), claim=claim(), profile=None
    )

    assert evidence.outcome is VerificationOutcome.UNAVAILABLE
