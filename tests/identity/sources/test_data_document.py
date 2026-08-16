from __future__ import annotations

import base64
import json
from urllib.parse import quote_from_bytes

import pytest


def _module():
    try:
        from agent_traffic_intelligence.identity.sources import data_document
    except ImportError:
        pytest.fail("bounded data-document parsing is not implemented")
    return data_document


def _directory_body() -> bytes:
    return json.dumps(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
                    "use": "sig",
                }
            ]
        },
        separators=(",", ":"),
    ).encode("utf-8")


def test_percent_encoded_directory_is_parsed_offline() -> None:
    module = _module()
    body = _directory_body()
    uri = (
        "data:application/http-message-signatures-directory+json,"
        + quote_from_bytes(body, safe="")
    )

    directory = module.parse_data_directory_uri(uri)

    assert len(directory.keys) == 1
    assert directory.keys[0].kty == "OKP"


def test_base64_directory_is_parsed_offline() -> None:
    module = _module()
    body = _directory_body()
    encoded = base64.b64encode(body).decode("ascii")
    uri = f"data:application/http-message-signatures-directory+json;base64,{encoded}"

    directory = module.parse_data_directory_uri(uri)

    assert len(directory.keys) == 1


def test_inline_agent_card_uses_application_json() -> None:
    module = _module()
    body = b'{"client_name":"Inline Bot","jwks_uri":"https://inline.example/keys"}'
    uri = "data:application/json," + quote_from_bytes(body, safe="")

    card = module.parse_data_card_uri(uri)

    assert card.client_name == "Inline Bot"
    assert card.jwks_uri == "https://inline.example/keys"


@pytest.mark.parametrize(
    ("parser_name", "uri"),
    [
        (
            "parse_data_directory_uri",
            "data:application/json,%7B%22keys%22%3A%5B%5D%7D",
        ),
        (
            "parse_data_card_uri",
            "data:text/plain,%7B%22client_name%22%3A%22Bot%22%7D",
        ),
        (
            "parse_data_directory_uri",
            "data:application/http-message-signatures-directory+json;utf8,%7B%22keys%22%3A%5B%5D%7D",
        ),
    ],
)
def test_wrong_media_type_or_invalid_bare_parameter_is_rejected(
    parser_name: str,
    uri: str,
) -> None:
    module = _module()
    parser = getattr(module, parser_name)

    with pytest.raises(module.DataDocumentError, match=r"media type|parameter"):
        parser(uri)


def test_size_limit_applies_to_decoded_bytes() -> None:
    module = _module()
    body = b'{"client_name":"' + (b"A" * 128) + b'"}'
    uri = "data:application/json;base64," + base64.b64encode(body).decode("ascii")

    with pytest.raises(module.DataDocumentError, match="size limit"):
        module.parse_data_card_uri(uri, max_bytes=32)


@pytest.mark.parametrize(
    "uri",
    [
        "data:application/json;base64,%%%",
        "data:application/json,%ZZ",
        "data:application/json",
        "https://example.com/card.json",
    ],
)
def test_malformed_data_uri_is_rejected_without_payload_echo(uri: str) -> None:
    module = _module()

    with pytest.raises(module.DataDocumentError) as exc_info:
        module.parse_data_card_uri(uri)

    message = str(exc_info.value)
    assert uri not in message
    assert len(message) < 160


def test_max_bytes_must_be_positive() -> None:
    module = _module()

    with pytest.raises(ValueError, match="max_bytes"):
        module.parse_data_card_uri("data:application/json,%7B%7D", max_bytes=0)
