"""Convert validated public JWKs into keys for RFC 9421 verification."""

from __future__ import annotations

import base64
import importlib
from collections.abc import Mapping
from typing import Any

from agent_traffic_intelligence.identity.crypto.directory import (
    DirectoryKey,
    KeyDirectory,
)
from agent_traffic_intelligence.identity.crypto.jwk_set import (
    JwkSet,
    JwkSetKey,
    select_jwk_set_key,
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


def _materialize_public_key(*, kty: str, jwk: Mapping[str, Any]) -> object:
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

    if kty == "OKP" and jwk.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(
            _decode_b64url(str(jwk["x"]))
        )
    if kty == "EC" and jwk.get("crv") == "P-256":
        x = _decode_int(str(jwk["x"]))
        y = _decode_int(str(jwk["y"]))
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    if kty == "RSA":
        modulus = _decode_int(str(jwk["n"]))
        exponent = _decode_int(str(jwk["e"]))
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()

    descriptor = f"{kty}/{jwk.get('crv')}"
    raise KeyMaterialUnavailable(f"unsupported Web Bot Auth JWK: {descriptor}")


class JwkKeyResolver:
    """Resolve strict HTTP Message Signatures Directory keys."""

    def __init__(self, directory: KeyDirectory) -> None:
        self._directory = directory

    def resolve_directory_key(self, key_id: str) -> DirectoryKey:
        return self._directory.by_id(key_id)

    def resolve_public_key(self, key_id: str) -> object:
        key = self.resolve_directory_key(key_id)
        return _materialize_public_key(kty=key.kty, jwk=key.jwk)

    def resolve_private_key(self, key_id: str) -> object:
        raise KeyMaterialUnavailable("private keys are never available")


class JwkSetKeyResolver:
    """Resolve generic RFC 7517 JWK Set keys by kid, then thumbprint."""

    def __init__(self, jwk_set: JwkSet) -> None:
        self._jwk_set = jwk_set

    def resolve_jwk_set_key(self, key_id: str) -> JwkSetKey:
        return select_jwk_set_key(self._jwk_set, key_id)

    def resolve_public_key(self, key_id: str) -> object:
        key = self.resolve_jwk_set_key(key_id)
        return _materialize_public_key(kty=key.kty, jwk=key.jwk)

    def resolve_private_key(self, key_id: str) -> object:
        raise KeyMaterialUnavailable("private keys are never available")
