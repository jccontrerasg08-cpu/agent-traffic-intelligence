"""RFC 9530 Content-Digest validation for fetched identity documents."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from typing import Any

from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentUnavailable,
    structured_fields_module,
)


class ContentDigestError(ValueError):
    """Raised when Content-Digest cannot validate the fetched body."""


_SUPPORTED: tuple[tuple[str, Callable[[bytes], Any]], ...] = (
    ("sha-512", hashlib.sha512),
    ("sha-256", hashlib.sha256),
)


def validate_content_digest(raw: str, body: bytes) -> str:
    """Validate at least one supported RFC 9530 digest over ``body``.

    RFC 9530 allows recipients to choose which conveyed digests to process.
    ATI accepts SHA-256 and SHA-512 and requires at least one conveyed,
    supported digest to match the exact fetched content bytes.
    """

    if not raw.strip():
        raise ContentDigestError("Content-Digest must be a valid RFC 9530 dictionary")

    try:
        structured_fields = structured_fields_module()
    except SignatureAgentUnavailable as exc:
        raise ContentDigestError("Structured Fields support is unavailable") from exc

    dictionary = structured_fields.Dictionary()
    try:
        dictionary.parse(raw.encode("utf-8"))
    except Exception as exc:
        raise ContentDigestError(
            "Content-Digest must be a valid RFC 9530 dictionary"
        ) from exc

    supported_present = False
    for algorithm, digest_factory in _SUPPORTED:
        member = dictionary.get(algorithm)
        if member is None:
            continue
        supported_present = True
        value = getattr(member, "value", None)
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise ContentDigestError(
                f"Content-Digest {algorithm} value must be a Byte Sequence"
            )
        expected = digest_factory(body).digest()
        if hmac.compare_digest(bytes(value), expected):
            return algorithm

    if not supported_present:
        raise ContentDigestError("Content-Digest must include sha-256 or sha-512")
    raise ContentDigestError("Content-Digest does not match response body")
