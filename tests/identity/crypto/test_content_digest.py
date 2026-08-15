from __future__ import annotations

import hashlib

import pytest

from agent_traffic_intelligence.identity.crypto.content_digest import (
    ContentDigestError,
    validate_content_digest,
)
from agent_traffic_intelligence.identity.crypto.signature_agent import (
    structured_fields_module,
)

pytest.importorskip("http_message_signatures")


def digest_field(body: bytes, algorithm: str) -> str:
    sf = structured_fields_module()
    digest = hashlib.new(algorithm.replace("-", ""), body).digest()
    return str(sf.Dictionary({algorithm: digest}))


def test_validates_sha256_content_digest() -> None:
    body = b'{"keys":[]}'

    assert validate_content_digest(digest_field(body, "sha-256"), body) == "sha-256"


def test_validates_sha512_content_digest() -> None:
    body = b'{"keys":[]}'

    assert validate_content_digest(digest_field(body, "sha-512"), body) == "sha-512"


def test_rejects_digest_that_does_not_match_body() -> None:
    raw = digest_field(b"original", "sha-256")

    with pytest.raises(ContentDigestError, match="does not match"):
        validate_content_digest(raw, b"tampered")


def test_rejects_malformed_or_unsupported_digest_dictionary() -> None:
    with pytest.raises(ContentDigestError, match="valid RFC 9530"):
        validate_content_digest("not-a-dictionary", b"body")

    sf = structured_fields_module()
    unsupported = str(sf.Dictionary({"md5": hashlib.md5(b"body").digest()}))
    with pytest.raises(ContentDigestError, match="sha-256 or sha-512"):
        validate_content_digest(unsupported, b"body")
