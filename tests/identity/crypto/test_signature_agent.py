from __future__ import annotations

import pytest

from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentDiscoveryType,
    SignatureAgentFormatError,
    SignatureAgentProfile,
    StructuredFieldSignatureAgentParser,
)

pytest.importorskip("http_message_signatures")


def test_current_profile_parses_all_standard_discovery_types() -> None:
    references = StructuredFieldSignatureAgentParser(
        profile=SignatureAgentProfile.IETF_HTTPSIG_PROTOCOL_01
    ).parse(
        'sig1="https://agent.example", '
        'sig2="https://agent.example/keys.json";type=jwks_uri, '
        'sig3="https://agent.example/bot";type=cimd'
    )

    assert [reference.label for reference in references] == ["sig1", "sig2", "sig3"]
    assert references[0].discovery_type is SignatureAgentDiscoveryType.DIRECTORY
    assert references[1].discovery_type is SignatureAgentDiscoveryType.JWKS_URI
    assert references[2].discovery_type is SignatureAgentDiscoveryType.CIMD
    assert all(reference.legacy is False for reference in references)


def test_current_profile_ignores_unknown_discovery_type_without_inference() -> None:
    references = StructuredFieldSignatureAgentParser(
        profile=SignatureAgentProfile.IETF_HTTPSIG_PROTOCOL_01
    ).parse(
        'future="https://agent.example/future";type=future_scheme, '
        'known="https://agent.example"'
    )

    assert len(references) == 1
    assert references[0].label == "known"
    assert references[0].discovery_type is SignatureAgentDiscoveryType.DIRECTORY


def test_current_profile_does_not_silently_downgrade_to_legacy() -> None:
    parser = StructuredFieldSignatureAgentParser(
        profile=SignatureAgentProfile.IETF_HTTPSIG_PROTOCOL_01
    )

    with pytest.raises(SignatureAgentFormatError, match="dictionary"):
        parser.parse('"https://agent.example"')


def test_cloudflare_legacy_profile_accepts_structured_string_only() -> None:
    parser = StructuredFieldSignatureAgentParser(
        profile=SignatureAgentProfile.CLOUDFLARE_LEGACY
    )

    references = parser.parse('"https://agent.example"')
    assert len(references) == 1
    assert references[0].label is None
    assert references[0].uri == "https://agent.example"
    assert references[0].discovery_type is SignatureAgentDiscoveryType.DIRECTORY
    assert references[0].legacy is True

    with pytest.raises(SignatureAgentFormatError, match="legacy"):
        parser.parse('sig1="https://agent.example"')


def test_rejects_empty_non_string_and_malformed_values() -> None:
    parser = StructuredFieldSignatureAgentParser(
        profile=SignatureAgentProfile.IETF_HTTPSIG_PROTOCOL_01
    )
    with pytest.raises(SignatureAgentFormatError, match="must not be empty"):
        parser.parse("   ")
    with pytest.raises(SignatureAgentFormatError, match="non-empty strings"):
        parser.parse("sig1=?1")
    with pytest.raises(SignatureAgentFormatError):
        parser.parse("sig1=(")
