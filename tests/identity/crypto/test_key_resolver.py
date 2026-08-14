from __future__ import annotations

import base64

import pytest

from agent_traffic_intelligence.identity.crypto.directory import parse_key_directory
from agent_traffic_intelligence.identity.crypto.key_resolver import JwkKeyResolver


def b64url_int(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def test_materializes_ed25519_public_key() -> None:
    pytest.importorskip("cryptography")
    directory = parse_key_directory(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
                }
            ]
        }
    )
    key = JwkKeyResolver(directory).resolve_public_key(directory.keys[0].key_id)
    assert key.__class__.__name__ == "Ed25519PublicKey"


def test_materializes_p256_and_rsa_public_keys() -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    ec_private = ec.generate_private_key(ec.SECP256R1())
    ec_numbers = ec_private.public_key().public_numbers()
    ec_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_int(ec_numbers.x),
        "y": b64url_int(ec_numbers.y),
    }
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_numbers = rsa_private.public_key().public_numbers()
    rsa_jwk = {
        "kty": "RSA",
        "n": b64url_int(rsa_numbers.n),
        "e": b64url_int(rsa_numbers.e),
    }
    directory = parse_key_directory({"keys": [ec_jwk, rsa_jwk]})
    resolver = JwkKeyResolver(directory)

    ec_key = resolver.resolve_public_key(directory.keys[0].key_id)
    rsa_key = resolver.resolve_public_key(directory.keys[1].key_id)
    assert ec_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    assert rsa_key.key_size == 2048
