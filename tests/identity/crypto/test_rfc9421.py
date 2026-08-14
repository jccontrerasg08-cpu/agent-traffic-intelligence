from __future__ import annotations

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.rfc9421 import Rfc9421Verifier
from agent_traffic_intelligence.identity.models import (
    SourceAddressProvenance,
    VerificationOutcome,
)


class StaticKeyResolver:
    def resolve_public_key(self, key_id: str) -> object:
        return b"test-key"


def context() -> VerificationContext:
    return VerificationContext(
        source_ip=None,
        source_address_provenance=SourceAddressProvenance.UNKNOWN,
        authority="example.com",
        method="GET",
        target_uri="https://example.com/docs",
        signature="sig1=:AAAA:",
        signature_input=(
            'sig1=("@authority");created=1786700000;keyid="key-1";'
            'alg="hmac-sha256";expires=1786700300;tag="web-bot-auth"'
        ),
        signature_agent=None,
        covered_headers={},
    )


def test_missing_optional_dependency_is_unavailable() -> None:
    result = Rfc9421Verifier(StaticKeyResolver()).verify(
        context(),
        algorithm_id="hmac-sha256",
        expect_tag="web-bot-auth",
    )

    assert result.outcome is VerificationOutcome.UNAVAILABLE
    assert result.label is None
    assert result.covered_component_names == frozenset()


def test_missing_signature_inputs_are_unavailable_before_crypto() -> None:
    empty = VerificationContext(
        source_ip=None,
        source_address_provenance=SourceAddressProvenance.UNKNOWN,
        authority="example.com",
        method="GET",
        target_uri="https://example.com/docs",
        signature=None,
        signature_input=None,
        signature_agent=None,
        covered_headers={},
    )
    result = Rfc9421Verifier(StaticKeyResolver()).verify(
        empty,
        algorithm_id="ed25519",
        expect_tag="web-bot-auth",
    )
    assert result.outcome is VerificationOutcome.UNAVAILABLE
