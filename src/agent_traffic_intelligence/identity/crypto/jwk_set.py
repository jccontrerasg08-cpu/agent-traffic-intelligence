"""Generic public JWK Set parsing for CIMD metadata."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from agent_traffic_intelligence.identity.crypto.directory import (
    DirectoryFormatError,
    jwk_thumbprint,
)


class JwkSetFormatError(ValueError):
    """Raised when a generic public JWK Set cannot be safely interpreted."""


class JwkSetKeySelectionError(LookupError):
    """Raised when a signature key cannot be selected unambiguously."""


@dataclass(frozen=True, slots=True)
class JwkSetKey:
    """Public JWK metadata with operator key ID and computed identity separated."""

    kid: str | None
    thumbprint: str
    kty: str
    alg: str | None
    use: str | None
    not_before: int | None
    expires: int | None
    jwk: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "jwk", MappingProxyType(dict(self.jwk)))
        if (
            self.not_before is not None
            and self.expires is not None
            and self.expires <= self.not_before
        ):
            raise JwkSetFormatError("JWK exp must be later than nbf")


@dataclass(frozen=True, slots=True)
class JwkSet:
    """A generic RFC 7517 JWK Set used by CIMD metadata."""

    keys: tuple[JwkSetKey, ...]


def _optional_string(jwk: Mapping[str, Any], name: str) -> str | None:
    value = jwk.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise JwkSetFormatError(f"JWK {name} must be a string when present")
    return value


def _optional_int(jwk: Mapping[str, Any], name: str) -> int | None:
    value = jwk.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise JwkSetFormatError(f"JWK {name} must be an integer when present")
    return value


def _parse_key(raw: Any) -> JwkSetKey:
    if not isinstance(raw, Mapping):
        raise JwkSetFormatError("each JWK Set key must be an object")
    if "d" in raw:
        raise JwkSetFormatError("JWK Set must not expose private JWK material")

    try:
        thumbprint = jwk_thumbprint(raw)
    except DirectoryFormatError as exc:
        raise JwkSetFormatError(str(exc)) from exc

    kty = raw.get("kty")
    if not isinstance(kty, str) or not kty:
        raise JwkSetFormatError("JWK kty must be a non-empty string")

    return JwkSetKey(
        kid=_optional_string(raw, "kid"),
        thumbprint=thumbprint,
        kty=kty,
        alg=_optional_string(raw, "alg"),
        use=_optional_string(raw, "use"),
        not_before=_optional_int(raw, "nbf"),
        expires=_optional_int(raw, "exp"),
        jwk=raw,
    )


def parse_jwk_set(payload: bytes | str | Mapping[str, Any]) -> JwkSet:
    """Parse a public RFC 7517 JWK Set without Directory-specific kid rules."""

    if isinstance(payload, bytes):
        try:
            decoded: Any = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JwkSetFormatError("JWK Set must be valid UTF-8 JSON") from exc
    elif isinstance(payload, str):
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise JwkSetFormatError("JWK Set must be valid JSON") from exc
    else:
        decoded = payload

    if not isinstance(decoded, Mapping):
        raise JwkSetFormatError("JWK Set must be a JSON object")
    raw_keys = decoded.get("keys")
    if not isinstance(raw_keys, list):
        raise JwkSetFormatError("JWK Set keys must be an array")

    keys = tuple(_parse_key(item) for item in raw_keys)
    thumbprints = [key.thumbprint for key in keys]
    if len(thumbprints) != len(set(thumbprints)):
        raise JwkSetFormatError("JWK Set contains duplicate public keys")
    return JwkSet(keys=keys)


def select_jwk_set_key(jwk_set: JwkSet, key_id: str) -> JwkSetKey:
    """Select one JWK by operator ``kid`` first, then computed thumbprint."""

    if not isinstance(key_id, str) or not key_id:
        raise JwkSetKeySelectionError("keyid must be a non-empty string")

    kid_matches = tuple(key for key in jwk_set.keys if key.kid == key_id)
    if len(kid_matches) == 1:
        return kid_matches[0]
    if len(kid_matches) > 1:
        raise JwkSetKeySelectionError("ambiguous JWK kid match")

    thumbprint_matches = tuple(
        key for key in jwk_set.keys if key.thumbprint == key_id
    )
    if len(thumbprint_matches) == 1:
        return thumbprint_matches[0]
    if len(thumbprint_matches) > 1:
        raise JwkSetKeySelectionError("ambiguous JWK thumbprint match")
    raise JwkSetKeySelectionError("keyid does not match any JWK")
