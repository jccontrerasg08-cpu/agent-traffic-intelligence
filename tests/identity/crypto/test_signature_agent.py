from __future__ import annotations

import pytest

from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentFormatError,
    StructuredFieldSignatureAgentParser,
)


def parser() -> StructuredFieldSignatureAgentParser:
    pytest.importorskip("http_sf")
    return StructuredFieldSignatureAgentParser()


def test_parses_current_dictionary_representation() -> None:
    refs = parser().parse(
        'sig1="https://agent.example/directory", '
        'cimd="https://agent.example/card";type="cimd"'
    )
    assert refs[0].label == "sig1"
    assert refs[0].uri == "https://agent.example/directory"
    assert refs[0].legacy is False
    assert refs[1].card_type == "cimd"


def test_parses_legacy_structured_string() -> None:
    refs = parser().parse('"https://agent.example/directory"')
    assert len(refs) == 1
    assert refs[0].label is None
    assert refs[0].legacy is True


def test_rejects_invalid_signature_agent() -> None:
    with pytest.raises(SignatureAgentFormatError):
        parser().parse("not valid structured fields !!!")
