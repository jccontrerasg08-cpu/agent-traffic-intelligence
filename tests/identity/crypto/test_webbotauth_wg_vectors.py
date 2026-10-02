"""Official test vectors from draft-ietf-webbotauth-httpsig-protocol-00, Appendix E.2.

These run the real verification chain (RFC 9421 cryptography, Structured Fields
parsing, Web Bot Auth policy and Signature-Agent binding) against signatures produced
by the draft's authors, not by this repository. They use the Ed25519 test key from
RFC 9421 Appendix B.1.4.

The vectors carry an `expires` decades away so they do not age. ATI's default policy
rejects any validity window longer than 24 hours, which the draft recommends, so these
tests widen that one limit explicitly; everything else is the default policy.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.directory import parse_key_directory
from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentProfile,
    StructuredFieldSignatureAgentParser,
)
from agent_traffic_intelligence.identity.crypto.web_bot_auth import (
    WebBotAuthPolicy,
    WebBotAuthVerifier,
)
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    SourceAddressProvenance,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.sources.trust import SourceTrustPolicy
from agent_traffic_intelligence.models import ActorType, IdentityClaim

pytest.importorskip("http_message_signatures")

SIGNATURE_AGENT = "https://signature-agent.test"
DIRECTORY_URI = f"{SIGNATURE_AGENT}/.well-known/http-message-signatures-directory"
# RFC 9421 Appendix B.1.4 test-key-ed25519, public part.
RFC9421_ED25519_PUBLIC_X = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
KEYID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
CREATED = 1735689600
VERIFIED_AT = datetime.fromtimestamp(CREATED + 600, tz=UTC)

# Appendix E.2.1: dictionary Signature-Agent, signature label sig2, member agent2.
DICTIONARY_VECTOR = {
    "signature_agent": f'agent2="{SIGNATURE_AGENT}"',
    "signature_input": (
        'sig2=("@authority" "signature-agent";key="agent2")'
        f';created={CREATED};keyid="{KEYID}";alg="ed25519";expires=4889289600'
        ';nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA=="'
        ';tag="web-bot-auth"'
    ),
    "signature": (
        "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8Ph"
        "bNZACSanGdhEwYCCg==:"
    ),
}

# Appendix E.2.2: legacy bare-string Signature-Agent.
LEGACY_VECTOR = {
    "signature_agent": f'"{SIGNATURE_AGENT}"',
    "signature_input": (
        'sig2=("@authority" "signature-agent")'
        f';created={CREATED};keyid="{KEYID}";alg="ed25519";expires=1735693200'
        ';nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg=="'
        ';tag="web-bot-auth"'
    ),
    "signature": (
        "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJ"
        "KuHxUi/5Syp3rLWBA==:"
    ),
}


def context(vector: dict[str, str]) -> VerificationContext:
    return VerificationContext(
        source_ip=None,
        source_address_provenance=SourceAddressProvenance.UNKNOWN,
        authority="example.com",
        method="GET",
        target_uri="https://example.com/",
        signature=vector["signature"],
        signature_input=vector["signature_input"],
        signature_agent=vector["signature_agent"],
        covered_headers={},
    )


def verifier(profile: SignatureAgentProfile) -> WebBotAuthVerifier:
    directory = parse_key_directory(
        {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": RFC9421_ED25519_PUBLIC_X}]}
    )
    return WebBotAuthVerifier(
        directory=directory,
        directory_uri=DIRECTORY_URI,
        signature_agent_uri=SIGNATURE_AGENT,
        binding_scope=BindingScope.AGENT,
        subject="TestAgent",
        trust_policy=SourceTrustPolicy(frozenset({DIRECTORY_URI})),
        signature_agent_parser=StructuredFieldSignatureAgentParser(profile=profile),
        policy=WebBotAuthPolicy(max_validity_seconds=100 * 365 * 24 * 60 * 60),
    )


def claim() -> IdentityClaim:
    return IdentityClaim(
        provider="test", agent="TestAgent", actor_type=ActorType.AI_USER_AGENT, intent="test"
    )


def test_the_directory_key_has_the_thumbprint_the_vectors_name() -> None:
    directory = parse_key_directory(
        {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": RFC9421_ED25519_PUBLIC_X}]}
    )

    assert directory.keys[0].key_id == KEYID


def test_dictionary_signature_agent_vector_verifies_and_binds() -> None:
    evidence = verifier(SignatureAgentProfile.IETF_HTTPSIG_PROTOCOL_01).verify(
        context=context(DICTIONARY_VECTOR), claim=claim(), now=VERIFIED_AT
    )

    assert evidence.outcome is VerificationOutcome.PASS, evidence.explanation
    assert evidence.details["signature_agent_bound"] is True
    assert evidence.details["legacy_signature_agent"] is False


def test_legacy_string_signature_agent_vector_verifies_under_the_legacy_profile() -> None:
    evidence = verifier(SignatureAgentProfile.CLOUDFLARE_LEGACY).verify(
        context=context(LEGACY_VECTOR), claim=claim(), now=VERIFIED_AT
    )

    assert evidence.outcome is VerificationOutcome.PASS, evidence.explanation
    assert evidence.details["legacy_signature_agent"] is True


def test_a_tampered_vector_signature_is_rejected() -> None:
    signature = DICTIONARY_VECTOR["signature"].replace("R", "S", 1)
    tampered = dict(DICTIONARY_VECTOR, signature=signature)

    evidence = verifier(SignatureAgentProfile.IETF_HTTPSIG_PROTOCOL_01).verify(
        context=context(tampered), claim=claim(), now=VERIFIED_AT
    )

    assert evidence.outcome is not VerificationOutcome.PASS


def test_the_vector_replayed_to_another_authority_is_rejected() -> None:
    # @authority is read from the target URI, which ingestion builds from the Host.
    wrong_authority = replace(
        context(DICTIONARY_VECTOR),
        authority="attacker.example",
        target_uri="https://attacker.example/",
    )

    evidence = verifier(SignatureAgentProfile.IETF_HTTPSIG_PROTOCOL_01).verify(
        context=wrong_authority, claim=claim(), now=VERIFIED_AT
    )

    assert evidence.outcome is not VerificationOutcome.PASS
