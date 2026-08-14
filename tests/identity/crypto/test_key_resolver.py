from __future__ import annotations

import base64

import pytest

from agent_traffic_intelligence.identity.crypto.directory import parse_key_directory
from agent_traffic_intelligence.identity.crypto.key_resolver import (
    JwkKeyResolver,
    KeyMaterialUnavailable,
)

ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
ec = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")
rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64int(value: int) -> str:
    size = max(1, (value.bit_length() + 7) // 8)
    return b64url(value.to_bytes(size, "big"))


def test_materializes_ed25519_public_key() -> None:
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    x = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    directory = parse_key_directory(
        {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": b64url(x)}]}
    )
    resolved = JwkKeyResolver(directory).resolve_public_key(directory.keys[0].key_id)
    assert isinstance(resolved, ed25519.Ed25519PublicKey)

    message = b"ati-ed25519-test"
    resolved.verify(private.sign(message), message)


def test_materializes_p256_public_key() -> None:
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    directory = parse_key_directory(
        {
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": b64int(numbers.x),
                    "y": b64int(numbers.y),
                }
            ]
        }
    )
    resolved = JwkKeyResolver(directory).resolve_public_key(directory.keys[0].key_id)
    assert isinstance(resolved, ec.EllipticCurvePublicKey)
    assert resolved.public_numbers() == numbers


def test_materializes_rsa_public_key() -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    directory = parse_key_directory(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "e": b64int(numbers.e),
                    "n": b64int(numbers.n),
                }
            ]
        }
    )
    resolved = JwkKeyResolver(directory).resolve_public_key(directory.keys[0].key_id)
    assert isinstance(resolved, rsa.RSAPublicKey)
    assert resolved.public_numbers() == numbers


def test_missing_or_unsupported_key_material_fails_closed() -> None:
    unsupported = parse_key_directory(
        {"keys": [{"kty": "EC", "crv": "P-384", "x": "AQ", "y": "Ag"}]}
    )
    resolver = JwkKeyResolver(unsupported)
    with pytest.raises(KeyMaterialUnavailable, match="unsupported"):
        resolver.resolve_public_key(unsupported.keys[0].key_id)
    with pytest.raises(KeyError):
        resolver.resolve_directory_key("missing")
