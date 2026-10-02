from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.rfc9421 import Rfc9421Verifier
from agent_traffic_intelligence.identity.models import (
    SourceAddressProvenance,
    VerificationOutcome,
)

hms = pytest.importorskip("http_message_signatures")
algorithms = pytest.importorskip("http_message_signatures.algorithms")
ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")


@dataclass
class Message:
    method: str
    url: str
    headers: dict[str, str]


class KeyResolver:
    def __init__(self) -> None:
        self.private = ed25519.Ed25519PrivateKey.generate()

    def resolve_private_key(self, key_id: str) -> object:
        if key_id != "test-key":
            raise KeyError(key_id)
        return self.private

    def resolve_public_key(self, key_id: str) -> object:
        if key_id != "test-key":
            raise KeyError(key_id)
        return self.private.public_key()


def context_from(message: Message) -> VerificationContext:
    return VerificationContext(
        source_ip=None,
        source_address_provenance=SourceAddressProvenance.UNKNOWN,
        authority="example.com",
        method=message.method,
        target_uri=message.url,
        signature=message.headers.get("Signature"),
        signature_input=message.headers.get("Signature-Input"),
        signature_agent=message.headers.get("Signature-Agent"),
        covered_headers={
            key: value
            for key, value in message.headers.items()
            if key.casefold() not in {"signature", "signature-input", "signature-agent"}
        },
    )


def signed_message(
    resolver: KeyResolver,
    *,
    covered: tuple[str, ...] = ("@authority",),
    signature_agent: str | None = None,
    created: datetime | None = None,
) -> Message:
    message = Message("GET", "https://example.com/docs?x=1", {})
    if signature_agent is not None:
        message.headers["Signature-Agent"] = signature_agent
    now = created or datetime.now(UTC)
    signer = hms.HTTPMessageSigner(
        signature_algorithm=algorithms.ED25519,
        key_resolver=resolver,
        component_resolver_class=Rfc9421Verifier._component_resolver(hms),
    )
    signer.sign(
        message,
        key_id="test-key",
        covered_component_ids=covered,
        created=now,
        expires=now + timedelta(minutes=5),
        nonce="ati-nonce",
        label="sig1",
        tag="web-bot-auth",
    )
    return message


def test_verifies_real_ed25519_signature_and_returns_signed_data() -> None:
    resolver = KeyResolver()
    message = signed_message(resolver)
    result = Rfc9421Verifier(resolver).verify(
        context_from(message),
        algorithm_id="ed25519",
        expect_tag="web-bot-auth",
        required_components=frozenset({"@authority"}),
    )
    assert result.outcome is VerificationOutcome.PASS
    assert result.algorithm_id == "ed25519"
    assert "@authority" in result.covered_component_names
    assert result.parameters["keyid"] == "test-key"
    assert result.nonce == "ati-nonce"


def test_verifies_structured_signature_agent_member() -> None:
    resolver = KeyResolver()
    component = '"signature-agent";key="sig1"'
    message = signed_message(
        resolver,
        covered=("@authority", component),
        signature_agent='sig1="https://agent.example"',
    )
    result = Rfc9421Verifier(resolver).verify(
        context_from(message),
        algorithm_id="ed25519",
        expect_tag="web-bot-auth",
        required_components=frozenset({"@authority", "signature-agent"}),
    )
    assert result.outcome is VerificationOutcome.PASS
    assert "signature-agent" in result.covered_component_names


def test_missing_headers_bad_policy_and_unknown_algorithm_are_neutral() -> None:
    resolver = KeyResolver()
    empty = Message("GET", "https://example.com/", {})
    verifier = Rfc9421Verifier(resolver)
    assert verifier.verify(
        context_from(empty),
        algorithm_id="ed25519",
        expect_tag="web-bot-auth",
    ).outcome is VerificationOutcome.UNAVAILABLE

    message = signed_message(resolver)
    assert verifier.verify(
        context_from(message),
        algorithm_id="ed25519",
        expect_tag="web-bot-auth",
        max_age_seconds=0,
    ).outcome is VerificationOutcome.ERROR
    assert verifier.verify(
        context_from(message),
        algorithm_id="not-an-algorithm",
        expect_tag="web-bot-auth",
    ).outcome is VerificationOutcome.UNAVAILABLE


def test_tampering_and_missing_required_component_are_mismatches() -> None:
    resolver = KeyResolver()
    verifier = Rfc9421Verifier(resolver)

    tampered = signed_message(resolver)
    tampered.headers["Signature"] = "sig1=:AAAA:"
    assert verifier.verify(
        context_from(tampered),
        algorithm_id="ed25519",
        expect_tag="web-bot-auth",
    ).outcome is VerificationOutcome.MISMATCH

    method_only = signed_message(resolver, covered=("@method",))
    assert verifier.verify(
        context_from(method_only),
        algorithm_id="ed25519",
        expect_tag="web-bot-auth",
        required_components=frozenset({"@authority"}),
    ).outcome is VerificationOutcome.MISMATCH


A_YEAR_AGO = datetime.now(UTC).replace(microsecond=0) - timedelta(days=365)


def verify_at(
    message: Message, resolver: KeyResolver, now: datetime | None, max_age: int = 86400
) -> VerificationOutcome:
    return Rfc9421Verifier(resolver).verify(
        context_from(message),
        algorithm_id="ed25519",
        expect_tag="web-bot-auth",
        max_age_seconds=max_age,
        now=now,
    ).outcome


def test_a_recorded_signature_is_judged_at_the_time_of_its_request() -> None:
    resolver = KeyResolver()
    message = signed_message(resolver, created=A_YEAR_AGO)

    assert verify_at(message, resolver, A_YEAR_AGO + timedelta(minutes=1)) is (
        VerificationOutcome.PASS
    )
    assert verify_at(message, resolver, None) is VerificationOutcome.MISMATCH


@pytest.mark.parametrize(
    ("offset", "max_age"),
    [
        (timedelta(minutes=-1), 86400),
        (timedelta(minutes=6), 86400),
        (timedelta(minutes=2), 60),
    ],
    ids=["created-in-the-future", "expired", "older-than-max-age"],
)
def test_the_time_window_is_enforced_at_the_given_time(
    offset: timedelta, max_age: int
) -> None:
    resolver = KeyResolver()
    message = signed_message(resolver, created=A_YEAR_AGO)

    assert verify_at(message, resolver, A_YEAR_AGO + offset, max_age) is (
        VerificationOutcome.MISMATCH
    )


@pytest.mark.parametrize(
    ("replacement", "reason"),
    [("", "missing"), ('created="soon";', "Malformed")],
)
def test_a_missing_or_malformed_created_is_rejected_at_the_given_time(
    replacement: str, reason: str
) -> None:
    resolver = KeyResolver()
    message = signed_message(resolver, created=A_YEAR_AGO)
    created = f"created={int(A_YEAR_AGO.timestamp())};"
    message.headers["Signature-Input"] = message.headers["Signature-Input"].replace(
        created, replacement
    )

    result = Rfc9421Verifier(resolver).verify(
        context_from(message),
        algorithm_id="ed25519",
        expect_tag="web-bot-auth",
        now=A_YEAR_AGO,
    )

    assert result.outcome is VerificationOutcome.MISMATCH
    assert reason in result.explanation


def test_a_naive_verification_time_is_refused() -> None:
    resolver = KeyResolver()
    with pytest.raises(ValueError, match="timezone-aware"):
        verify_at(signed_message(resolver), resolver, datetime(2026, 1, 1))
