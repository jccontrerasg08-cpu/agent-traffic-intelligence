"""JWKS directory parsing and RFC 7638 thumbprints for Web Bot Auth."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any


class DirectoryFormatError(ValueError):
    """Raised when a key directory cannot be safely interpreted."""


def _b64url_sha256(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def _thumbprint_members(jwk: Mapping[str, Any]) -> dict[str, str]:
    kty = jwk.get("kty")
    if kty == "OKP":
        names = ("crv", "kty", "x")
    elif kty == "EC":
        names = ("crv", "kty", "x", "y")
    elif kty == "RSA":
        names = ("e", "kty", "n")
    else:
        raise DirectoryFormatError(f"unsupported public JWK kty: {kty!r}")
    result: dict[str, str] = {}
    for name in names:
        value = jwk.get(name)
        if not isinstance(value, str) or not value:
            raise DirectoryFormatError(f"JWK {name} must be a non-empty string")
        result[name] = value
    return result


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """Return the RFC 7638 SHA-256 JWK thumbprint as base64url without padding."""

    canonical = json.dumps(
        _thumbprint_members(jwk),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _b64url_sha256(canonical)


@dataclass(frozen=True, slots=True)
class DirectoryKey:
    """One public signing key from a Web Bot Auth key directory."""

    key_id: str
    kty: str
    alg: str | None
    use: str | None
    not_before: int | None
    expires: int | None
    jwk: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "jwk", MappingProxyType(dict(self.jwk)))
        if self.use not in (None, "sig"):
            raise DirectoryFormatError("directory key use must be 'sig' when present")
        if self.not_before is not None and self.expires is not None:
            if self.expires <= self.not_before:
                raise DirectoryFormatError("directory key exp must be later than nbf")

    def active_at(self, when: datetime) -> bool:
        if when.tzinfo is None or when.utcoffset() is None:
            raise ValueError("key activity time must be timezone-aware")
        timestamp = int(when.timestamp())
        if self.not_before is not None and timestamp < self.not_before:
            return False
        return self.expires is None or timestamp < self.expires


@dataclass(frozen=True, slots=True)
class KeyDirectory:
    keys: tuple[DirectoryKey, ...]
    profile: str = "draft-meunier-http-message-signatures-directory-05"

    def by_id(self, key_id: str) -> DirectoryKey:
        matches = [key for key in self.keys if key.key_id == key_id]
        if len(matches) != 1:
            raise KeyError(key_id)
        return matches[0]


def _optional_int(jwk: Mapping[str, Any], name: str) -> int | None:
    value = jwk.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise DirectoryFormatError(f"JWK {name} must be an integer")
    return value


def _parse_key(raw: Any) -> DirectoryKey:
    if not isinstance(raw, dict):
        raise DirectoryFormatError("each JWKS key must be an object")
    if "d" in raw:
        raise DirectoryFormatError("key directories must not expose private JWK material")
    thumbprint = jwk_thumbprint(raw)
    kid = raw.get("kid")
    if kid is not None and kid != thumbprint:
        raise DirectoryFormatError("JWK kid must equal its RFC 7638 thumbprint")
    alg = raw.get("alg")
    if alg is not None and not isinstance(alg, str):
        raise DirectoryFormatError("JWK alg must be a string when present")
    use = raw.get("use")
    if use is not None and not isinstance(use, str):
        raise DirectoryFormatError("JWK use must be a string when present")
    return DirectoryKey(
        key_id=thumbprint,
        kty=str(raw["kty"]),
        alg=alg,
        use=use,
        not_before=_optional_int(raw, "nbf"),
        expires=_optional_int(raw, "exp"),
        jwk=raw,
    )


def parse_key_directory(payload: bytes | str | Mapping[str, Any]) -> KeyDirectory:
    """Parse a JWKS directory, rejecting private/ambiguous key material."""

    if isinstance(payload, bytes):
        try:
            decoded: Any = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DirectoryFormatError("directory must be valid UTF-8 JSON") from exc
    elif isinstance(payload, str):
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise DirectoryFormatError("directory must be valid JSON") from exc
    else:
        decoded = payload
    if not isinstance(decoded, Mapping):
        raise DirectoryFormatError("directory must be a JSON object")
    raw_keys = decoded.get("keys")
    if not isinstance(raw_keys, list):
        raise DirectoryFormatError("directory keys must be an array")
    keys = tuple(_parse_key(item) for item in raw_keys)
    ids = [key.key_id for key in keys]
    if len(ids) != len(set(ids)):
        raise DirectoryFormatError("directory contains duplicate JWK thumbprints")
    return KeyDirectory(keys=keys)
