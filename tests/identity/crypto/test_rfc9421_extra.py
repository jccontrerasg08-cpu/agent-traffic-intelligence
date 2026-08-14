from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.rfc9421 import Rfc9421Verifier
from agent_traffic_intelligence.identity.models import (
    SourceAddressProvenance,
    VerificationOutcome,
)


class KeyResolver:
    key = b"0123456789abcdef0123456789abcdef"

    def resolve_public_key(self, key_id: str) -> object:
        if key_id != "key-1":
            raise KeyError(key_id)
        return self.key

    def resolve_private_key(self, key_id: str) -> object:
        if key_id != "key-1":
            raise KeyError(key_id)
        return self.key


class Message:
    def __init__(self) -> None:
        self.method = "GET"
        self.url = "https://example.com/docs"
        self.headers = {"Signature-Agent": 'agent="https://agent.example/directory"'}


def signed_context(
    *, covered: tuple[str, ...] = ("@authority", "signature-agent")
) -> tuple[VerificationContext, Message]:
    hms = pytest.importorskip("http_message_signatures")
    message = Message()
    signer = hms.HTTPMessageSigner(
        signature_algorithm=hms.algorithms.HMAC_SHA256,
        key_resolver=KeyResolver(),
    )
    now = datetime.now(UTC)
    signer.sign(
        message,
        key_id="key-1",
        created=now,
        expires=now + timedelta(minutes=5),
        tag="web-bot-auth",
        label="sig1",
        covered_component_ids=covered,
    )
    return (
        VerificationContext(
            source_ip=None,
            source_address_provenance=SourceAddressProvenance.UNKNOWN,
            authority="example.com",
            method="GET",
            target_uri=message.url,
            signature=message.headers["Signature"],
            signature_input=message.headers["Signature-Input"],
            signature_agent=message.headers["Signature-Agent"],
            covered_headers={},
        ),
        message,
    )


def test_valid_signature_returns_only_covered_material() -> None:
    signed, _message = signed_context()
    result = Rfc9421Verifier(KeyResolver()).verify(
        signed,
        algorithm_id="hmac-sha256",
        expect_tag="web-bot-auth",
        required_components=frozenset({"@authority", "signature-agent"}),
    )

    assert result.outcome is VerificationOutcome.PASS
    assert result.algorithm_id == "hmac-sha256"
    assert result.covered_component_names == frozenset({"@authority", "signature-agent"})
    assert result.parameters["tag"] == "web-bot-auth"


def test_tampered_authority_fails_signature() -> None:
    signed, _message = signed_context()
    tampered = VerificationContext(
        source_ip=None,
        source_address_provenance=SourceAddressProvenance.UNKNOWN,
        authority="attacker.example",
        method=signed.method,
        target_uri="https://attacker.example/docs",
        signature=signed.signature,
        signature_input=signed.signature_input,
        signature_agent=signed.signature_agent,
        covered_headers=signed.covered_headers,
    )
    result = Rfc9421Verifier(KeyResolver()).verify(
        tampered,
        algorithm_id="hmac-sha256",
        expect_tag="web-bot-auth",
    )
    assert result.outcome is VerificationOutcome.MISMATCH


def test_valid_signature_with_insufficient_coverage_is_rejected() -> None:
    signed, _message = signed_context(covered=("@method",))
    result = Rfc9421Verifier(KeyResolver()).verify(
        signed,
        algorithm_id="hmac-sha256",
        expect_tag="web-bot-auth",
        required_components=frozenset({"@authority"}),
    )
    assert result.outcome is VerificationOutcome.MISMATCH


def test_wrong_tag_is_rejected() -> None:
    signed, _message = signed_context()
    result = Rfc9421Verifier(KeyResolver()).verify(
        signed,
        algorithm_id="hmac-sha256",
        expect_tag="another-app",
    )
    assert result.outcome is VerificationOutcome.MISMATCH


def test_unsupported_algorithm_is_unavailable() -> None:
    signed, _message = signed_context()
    result = Rfc9421Verifier(KeyResolver()).verify(
        signed,
        algorithm_id="made-up-algorithm",
        expect_tag="web-bot-auth",
    )
    assert result.outcome is VerificationOutcome.UNAVAILABLE
