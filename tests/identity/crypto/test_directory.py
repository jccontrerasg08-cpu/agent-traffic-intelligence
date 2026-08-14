from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest

from agent_traffic_intelligence.identity.crypto.directory import (
    DirectoryFormatError,
    jwk_thumbprint,
    parse_key_directory,
)


def ed25519_jwk(**extra: object) -> dict[str, object]:
    raw = bytes(range(32))
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return {"kty": "OKP", "crv": "Ed25519", "x": x, **extra}


def test_directory_computes_thumbprint_when_kid_is_absent() -> None:
    jwk = ed25519_jwk(use="sig", nbf=1786700000, exp=1786703600)
    directory = parse_key_directory({"keys": [jwk], "future": True})
    key = directory.keys[0]
    assert key.key_id == jwk_thumbprint(jwk)
    assert key.active_at(datetime.fromtimestamp(1786700100, tz=UTC)) is True


def test_mismatched_explicit_kid_is_rejected() -> None:
    with pytest.raises(DirectoryFormatError, match="thumbprint"):
        parse_key_directory({"keys": [ed25519_jwk(kid="not-the-thumbprint")]})


def test_private_key_material_is_rejected() -> None:
    with pytest.raises(DirectoryFormatError, match="private"):
        parse_key_directory({"keys": [ed25519_jwk(d="secret")]})


def test_duplicate_thumbprints_are_rejected() -> None:
    jwk = ed25519_jwk()
    with pytest.raises(DirectoryFormatError, match="duplicate"):
        parse_key_directory({"keys": [jwk, jwk]})
