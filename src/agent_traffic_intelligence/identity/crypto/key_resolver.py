"""Convert validated directory JWKs into public keys for RFC 9421 verification."""

from __future__ import annotations

import base64
import importlib

from agent_traffic_intelligence.identity.crypto.directory import (
    DirectoryKey,
    KeyDirectory,
)


class KeyMaterialUnavailable(LookupError):
    """Raised when a supported public key cannot be materialized."""


def _decode_b64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise KeyMaterialUnavailable("JWK contains invalid base64url material") from exc


def _decode_int(value: str) -> int:
    raw = _decode_b64url(value)
    if not raw:
        raise KeyMaterialUnavailable("JWK integer material must not be empty")
    return int.from_bytes(raw, "big")


class JwkKeyResolver:
    def __init__(self, directory: KeyDirectory) -> None:
        self._directory = directory

    def resolve_directory_key(self, key_id: str) -> DirectoryKey:
        return self._directory.by_id(key_id)

    def resolve_public_key(self, key_id: str) -> object:
        key = self.resolve_directory_key(key_id)
        try:
            ed25519 = importlib.import_module(
                "cryptography.hazmat.primitives.asymmetric.ed25519"
            )
            ec = importlib.import_module("cryptography.hazmat.primitives.asymmetric.ec")
            rsa = importlib.import_module("cryptography.hazmat.primitives.asymmetric.rsa")
        except ImportError as exc:
            raise KeyMaterialUnavailable(
                "optional cryptography dependency is not installed"
            ) from exc

        if key.kty == "OKP" and key.jwk.get("crv") == "Ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(
                _decode_b64url(str(key.jwk["x"]))
            )
        if key.kty == "EC" and key.jwk.get("crv") == "P-256":
            x = _decode_int(str(key.jwk["x"]))
            y = _decode_int(str(key.jwk["y"]))
            return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        if key.kty == "RSA":
            modulus = _decode_int(str(key.jwk["n"]))
            exponent = _decode_int(str(key.jwk["e"]))
            return rsa.RSAPublicNumbers(exponent, modulus).public_key()

        descriptor = f"{key.kty}/{key.jwk.get('crv')}"
        raise KeyMaterialUnavailable(f"unsupported Web Bot Auth JWK: {descriptor}")
