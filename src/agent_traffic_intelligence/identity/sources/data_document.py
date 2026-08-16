"""Bounded offline parsing for trusted ``data:`` discovery documents."""

from __future__ import annotations

import base64
import binascii
import string
from urllib.parse import unquote_to_bytes

from agent_traffic_intelligence.identity.crypto.agent_card import (
    AgentCard,
    AgentCardFormatError,
    parse_agent_card,
)
from agent_traffic_intelligence.identity.crypto.directory import (
    DirectoryFormatError,
    KeyDirectory,
    parse_key_directory,
)

DEFAULT_MAX_DATA_BYTES = 64 * 1024
_DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"
_CARD_MEDIA_TYPE = "application/json"
_HEX_DIGITS = frozenset(string.hexdigits)


class DataDocumentError(ValueError):
    """Raised when a bounded offline ``data:`` document is not acceptable."""


def parse_data_directory_uri(
    uri: str,
    *,
    max_bytes: int = DEFAULT_MAX_DATA_BYTES,
) -> KeyDirectory:
    """Parse an inline HTTP Message Signatures Directory without network I/O."""

    body = _decode_data_uri(
        uri,
        expected_media_type=_DIRECTORY_MEDIA_TYPE,
        max_bytes=max_bytes,
    )
    try:
        return parse_key_directory(body)
    except DirectoryFormatError as exc:
        raise DataDocumentError("data directory is not a valid key directory") from exc


def parse_data_card_uri(
    uri: str,
    *,
    max_bytes: int = DEFAULT_MAX_DATA_BYTES,
) -> AgentCard:
    """Parse an inline Signature Agent Card without network I/O."""

    body = _decode_data_uri(
        uri,
        expected_media_type=_CARD_MEDIA_TYPE,
        max_bytes=max_bytes,
    )
    try:
        return parse_agent_card(body)
    except AgentCardFormatError as exc:
        raise DataDocumentError("data agent card is invalid") from exc


def _decode_data_uri(
    uri: str,
    *,
    expected_media_type: str,
    max_bytes: int,
) -> bytes:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if not isinstance(uri, str) or not uri[:5].casefold() == "data:":
        raise DataDocumentError("value must use the data URI scheme")

    header, separator, payload = uri[5:].partition(",")
    if not separator:
        raise DataDocumentError("data URI is missing its payload separator")

    media_type, is_base64 = _parse_metadata(
        header,
        expected_media_type=expected_media_type,
    )
    if media_type != expected_media_type:
        raise DataDocumentError("data URI has an unsupported media type")

    _validate_percent_escapes(payload)
    if len(payload) > (max_bytes * 4) + 16:
        raise DataDocumentError("data URI exceeds size limit")

    encoded = unquote_to_bytes(payload)
    if is_base64:
        try:
            encoded_ascii = encoded.decode("ascii")
            body = base64.b64decode(encoded_ascii, validate=True)
        except (UnicodeDecodeError, binascii.Error, ValueError) as exc:
            raise DataDocumentError("data URI base64 payload is invalid") from exc
    else:
        body = encoded

    if len(body) > max_bytes:
        raise DataDocumentError("data URI exceeds size limit")
    return body


def _parse_metadata(
    header: str,
    *,
    expected_media_type: str,
) -> tuple[str, bool]:
    parts = header.split(";")
    media_type = parts[0].strip().casefold()
    if media_type != expected_media_type:
        raise DataDocumentError("data URI has an unsupported media type")

    is_base64 = False
    for raw_part in parts[1:]:
        part = raw_part.strip()
        if not part:
            raise DataDocumentError("data URI contains an invalid media type parameter")
        if part.casefold() == "base64":
            if is_base64:
                raise DataDocumentError("data URI contains a duplicate base64 parameter")
            is_base64 = True
            continue
        name, separator, value = part.partition("=")
        if not separator or not name.strip() or not value:
            raise DataDocumentError("data URI contains an invalid media type parameter")
    return media_type, is_base64


def _validate_percent_escapes(payload: str) -> None:
    index = 0
    while True:
        index = payload.find("%", index)
        if index < 0:
            return
        if index + 2 >= len(payload):
            raise DataDocumentError("data URI contains an invalid percent escape")
        if payload[index + 1] not in _HEX_DIGITS or payload[index + 2] not in _HEX_DIGITS:
            raise DataDocumentError("data URI contains an invalid percent escape")
        index += 3
