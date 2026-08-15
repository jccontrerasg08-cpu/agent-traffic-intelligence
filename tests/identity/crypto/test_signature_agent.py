from __future__ import annotations

import pytest

from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentFormatError,
    SignatureAgentProfile,
    StructuredFieldSignatureAgentParser,
)

pytest.importorskip("http_message_signatures")


def test_ietf_directory_profile_parses_structured_dictionary() -> None:
    references = StructuredFieldSignatureAgentParser(
        profile=SignatureAgentProfile.IETF_DIRECTORY_05
    ).parse('sig1="https://agent.example", sig2="https://other.example"')

    assert [reference.label for reference in references] == ["sig1", "sig2"]
    assert references[0].uri == "https://agent.example"
    assert references[0].card_type is None
    assert references[0].legacy is False


def test_ietf_cimd_profile_requires_type_cimd() -> None:
    parser = StructuredFieldSignatureAgentParser(
        profile=SignatureAgentProfile.IETF_CIMD_REGISTRY_03
    )

    references = parser.parse('sig1="https://agent.example/bot";type=cimd')
    assert references[0].label == "sig1"
    assert references[0].uri == "https://agent.example/bot"
    assert references[0].card_type == "cimd"
    assert references[0].legacy is False

    with pytest.raises(SignatureAgentFormatError, match="type=cimd"):
        parser.parse('sig1="https://agent.example/bot"')


def test_current_ietf_profile_never_silently_downgrades_to_legacy() -> None:
    parser = StructuredFieldSignatureAgentParser(
        profile=SignatureAgentProfile.IETF_DIRECTORY_05
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
    assert references[0].legacy is True

    with pytest.raises(SignatureAgentFormatError, match="legacy"):
        parser.parse('sig1="https://agent.example"')


def test_rejects_empty_non_string_and_malformed_values() -> None:
    parser = StructuredFieldSignatureAgentParser(
        profile=SignatureAgentProfile.IETF_DIRECTORY_05
    )
    with pytest.raises(SignatureAgentFormatError, match="must not be empty"):
        parser.parse("   ")
    with pytest.raises(SignatureAgentFormatError, match="non-empty strings"):
        parser.parse("sig1=?1")
    with pytest.raises(SignatureAgentFormatError):
        parser.parse("sig1=(")
