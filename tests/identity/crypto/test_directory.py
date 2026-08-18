from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent_traffic_intelligence.identity.crypto.directory import (
    DirectoryFormatError,
    DirectoryKey,
    jwk_thumbprint,
    parse_key_directory,
)


def okp_jwk() -> dict[str, object]:
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
    }


def test_thumbprints_supported_public_key_types() -> None:
    assert jwk_thumbprint(okp_jwk())
    assert jwk_thumbprint(
        {"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value"}
    )
    assert jwk_thumbprint({"kty": "RSA", "e": "AQAB", "n": "modulus"})


def test_thumbprint_rejects_unsupported_or_incomplete_jwk() -> None:
    with pytest.raises(DirectoryFormatError, match="unsupported"):
        jwk_thumbprint({"kty": "oct", "k": "secret"})
    with pytest.raises(DirectoryFormatError, match="JWK x"):
        jwk_thumbprint({"kty": "OKP", "crv": "Ed25519"})


def test_directory_rejects_private_material_and_bad_metadata() -> None:
    private = {**okp_jwk(), "d": "private"}
    with pytest.raises(DirectoryFormatError, match="private"):
        parse_key_directory({"keys": [private]})

    opaque_kid = {**okp_jwk(), "kid": "operator-directory-key"}
    parsed = parse_key_directory({"keys": [opaque_kid]})
    assert parsed.keys[0].key_id == "operator-directory-key"
    assert parsed.keys[0].thumbprint == jwk_thumbprint(opaque_kid)

    with pytest.raises(DirectoryFormatError, match="kid"):
        parse_key_directory({"keys": [{**okp_jwk(), "kid": 1}]})

    with pytest.raises(DirectoryFormatError, match="alg"):
        parse_key_directory({"keys": [{**okp_jwk(), "alg": 1}]})
    with pytest.raises(DirectoryFormatError, match="use"):
        parse_key_directory({"keys": [{**okp_jwk(), "use": 1}]})
    with pytest.raises(DirectoryFormatError, match="integer"):
        parse_key_directory({"keys": [{**okp_jwk(), "nbf": "soon"}]})


def test_directory_key_validates_use_window_and_activity() -> None:
    now = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
    timestamp = int(now.timestamp())
    key = DirectoryKey(
        key_id="key",
        kty="OKP",
        alg="EdDSA",
        use="sig",
        not_before=timestamp - 60,
        expires=timestamp + 60,
        jwk=okp_jwk(),
    )
    assert key.active_at(now) is True
    assert key.active_at(datetime.fromtimestamp(timestamp - 120, tz=UTC)) is False
    assert key.active_at(datetime.fromtimestamp(timestamp + 120, tz=UTC)) is False

    with pytest.raises(ValueError, match="timezone-aware"):
        key.active_at(datetime(2026, 8, 14, 12, 0))
    with pytest.raises(DirectoryFormatError, match="use"):
        DirectoryKey("key", "OKP", None, "enc", None, None, okp_jwk())
    with pytest.raises(DirectoryFormatError, match="later"):
        DirectoryKey("key", "OKP", None, "sig", 10, 10, okp_jwk())


def test_directory_parsing_rejects_invalid_shapes_and_duplicates() -> None:
    for payload in (b"not-json", "not-json", [], {"keys": "not-a-list"}):
        with pytest.raises(DirectoryFormatError):
            parse_key_directory(payload)

    with pytest.raises(DirectoryFormatError, match="object"):
        parse_key_directory({"keys": ["not-an-object"]})
    with pytest.raises(DirectoryFormatError, match="duplicate"):
        parse_key_directory({"keys": [okp_jwk(), okp_jwk()]})

    duplicate_kids = [
        {**okp_jwk(), "kid": "operator-key"},
        {**okp_jwk(), "x": "other-public-key", "kid": "operator-key"},
    ]
    with pytest.raises(DirectoryFormatError, match="key identifiers"):
        parse_key_directory({"keys": duplicate_kids})


def test_directory_lookup_requires_exactly_one_key() -> None:
    directory = parse_key_directory({"keys": [okp_jwk()]})
    key = directory.keys[0]
    assert directory.by_id(key.key_id) is key
    with pytest.raises(KeyError):
        directory.by_id("missing")
