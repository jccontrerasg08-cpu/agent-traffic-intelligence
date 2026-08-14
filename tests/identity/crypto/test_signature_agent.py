from __future__ import annotations

import pytest

from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentFormatError,
    StructuredFieldSignatureAgentParser,
)

pytest.importorskip("http_sf")


def test_parses_structured_dictionary_and_parameters() -> None:
    references = StructuredFieldSignatureAgentParser().parse(
        'sig1="https://agent.example";type="crawler", sig2="https://other.example"'
    )
    assert [reference.label for reference in references] == ["sig1", "sig2"]
    assert references[0].uri == "https://agent.example"
    assert references[0].card_type == "crawler"
    assert references[0].legacy is False


def test_legacy_string_is_explicitly_marked() -> None:
    references = StructuredFieldSignatureAgentParser().parse('"https://agent.example"')
    assert len(references) == 1
    assert references[0].label is None
    assert references[0].uri == "https://agent.example"
    assert references[0].legacy is True


def test_rejects_empty_non_string_and_malformed_values() -> None:
    parser = StructuredFieldSignatureAgentParser()
    with pytest.raises(SignatureAgentFormatError, match="must not be empty"):
        parser.parse("   ")
    with pytest.raises(SignatureAgentFormatError, match="non-empty strings"):
        parser.parse("sig1=?1")
    with pytest.raises(SignatureAgentFormatError):
        parser.parse("sig1=(")
