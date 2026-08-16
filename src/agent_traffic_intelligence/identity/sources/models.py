"""Immutable external-source provenance models."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from agent_traffic_intelligence.identity.models import BindingScope


class SourceType(StrEnum):
    IP_RANGES = "ip_ranges"
    KEY_DIRECTORY = "key_directory"
    AGENT_CARD = "agent_card"
    STANDARD_PROFILE = "standard_profile"


class ValidationStatus(StrEnum):
    UNVALIDATED = "unvalidated"
    VALID = "valid"
    INVALID = "invalid"
    STALE = "stale"


class SourceAcquisition(StrEnum):
    """How ATI obtained source bytes for URL-to-key attribution decisions."""

    UNKNOWN = "unknown"


def _aware(value: datetime | None, name: str) -> None:
    if value is not None and (value.tzinfo is None or value.utcoffset() is None):
        raise ValueError(f"{name} must be timezone-aware")


def _sha256(value: str, name: str) -> str:
    digest = value.casefold()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"{name} must be a 64-character hexadecimal SHA-256")
    return digest


@dataclass(frozen=True, slots=True)
class KeyAuthorityBinding:
    """Derived proof that one public key was bound to a source authority/body."""

    key_thumbprint: str
    authority: str
    body_sha256: str
    verified_at: datetime
    expires_at: datetime | None
    profile: str

    def __post_init__(self) -> None:
        _aware(self.verified_at, "verified_at")
        _aware(self.expires_at, "expires_at")
        object.__setattr__(self, "body_sha256", _sha256(self.body_sha256, "body_sha256"))
        if not self.key_thumbprint:
            raise ValueError("key_thumbprint must not be empty")
        if not self.authority:
            raise ValueError("authority must not be empty")
        if not self.profile:
            raise ValueError("profile must not be empty")
        if self.expires_at is not None and self.expires_at <= self.verified_at:
            raise ValueError("expires_at must be later than verified_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_thumbprint": self.key_thumbprint,
            "authority": self.authority,
            "body_sha256": self.body_sha256,
            "verified_at": self.verified_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "profile": self.profile,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> KeyAuthorityBinding:
        verified_raw = payload.get("verified_at")
        if not isinstance(verified_raw, str):
            raise ValueError("verified_at must be an ISO-8601 string")
        expires_raw = payload.get("expires_at")
        if expires_raw is not None and not isinstance(expires_raw, str):
            raise ValueError("expires_at must be an ISO-8601 string or null")
        return cls(
            key_thumbprint=str(payload["key_thumbprint"]),
            authority=str(payload["authority"]),
            body_sha256=str(payload["body_sha256"]),
            verified_at=datetime.fromisoformat(verified_raw),
            expires_at=datetime.fromisoformat(expires_raw) if expires_raw else None,
            profile=str(payload["profile"]),
        )


@dataclass(frozen=True, slots=True)
class SourceMetadata:
    uri: str
    source_type: SourceType
    provider: str | None
    binding_scope: BindingScope
    retrieved_at: datetime
    sha256: str
    content_type: str | None
    parser_profile: str
    source_created_at: datetime | None = None
    expires_at: datetime | None = None
    etag: str | None = None
    last_modified: str | None = None
    validation_status: ValidationStatus = ValidationStatus.UNVALIDATED
    key_authority_bindings: tuple[KeyAuthorityBinding, ...] = ()
    acquisition: SourceAcquisition = SourceAcquisition.UNKNOWN

    def __post_init__(self) -> None:
        _aware(self.retrieved_at, "retrieved_at")
        _aware(self.source_created_at, "source_created_at")
        _aware(self.expires_at, "expires_at")
        object.__setattr__(self, "sha256", _sha256(self.sha256, "sha256"))
        object.__setattr__(self, "key_authority_bindings", tuple(self.key_authority_bindings))
        if not self.uri:
            raise ValueError("uri must not be empty")
        if not self.parser_profile:
            raise ValueError("parser_profile must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "uri": self.uri,
            "source_type": self.source_type.value,
            "provider": self.provider,
            "binding_scope": self.binding_scope.value,
            "retrieved_at": self.retrieved_at.isoformat(),
            "sha256": self.sha256,
            "content_type": self.content_type,
            "parser_profile": self.parser_profile,
            "source_created_at": (
                self.source_created_at.isoformat() if self.source_created_at else None
            ),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "etag": self.etag,
            "last_modified": self.last_modified,
            "validation_status": self.validation_status.value,
            "key_authority_bindings": [
                binding.to_dict() for binding in self.key_authority_bindings
            ],
            "acquisition": self.acquisition.value,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> SourceMetadata:
        def parse_dt(name: str) -> datetime | None:
            value = payload.get(name)
            if value is None:
                return None
            if not isinstance(value, str):
                raise ValueError(f"{name} must be an ISO-8601 string or null")
            return datetime.fromisoformat(value)

        retrieved = parse_dt("retrieved_at")
        if retrieved is None:
            raise ValueError("retrieved_at is required")
        bindings_raw = payload.get("key_authority_bindings", [])
        if not isinstance(bindings_raw, list):
            raise ValueError("key_authority_bindings must be a list")
        bindings = tuple(
            KeyAuthorityBinding.from_dict(item)
            for item in bindings_raw
            if isinstance(item, dict)
        )
        if len(bindings) != len(bindings_raw):
            raise ValueError("each key_authority_binding must be an object")
        return cls(
            uri=str(payload["uri"]),
            source_type=SourceType(str(payload["source_type"])),
            provider=str(payload["provider"]) if payload.get("provider") is not None else None,
            binding_scope=BindingScope(str(payload["binding_scope"])),
            retrieved_at=retrieved,
            sha256=str(payload["sha256"]),
            content_type=(
                str(payload["content_type"])
                if payload.get("content_type") is not None
                else None
            ),
            parser_profile=str(payload["parser_profile"]),
            source_created_at=parse_dt("source_created_at"),
            expires_at=parse_dt("expires_at"),
            etag=str(payload["etag"]) if payload.get("etag") is not None else None,
            last_modified=(
                str(payload["last_modified"])
                if payload.get("last_modified") is not None
                else None
            ),
            validation_status=ValidationStatus(
                str(payload.get("validation_status", "unvalidated"))
            ),
            key_authority_bindings=bindings,
            acquisition=SourceAcquisition(str(payload.get("acquisition", "unknown"))),
        )


@dataclass(frozen=True, slots=True)
class SourceDocument:
    metadata: SourceMetadata
    content: bytes

    def __post_init__(self) -> None:
        digest = hashlib.sha256(self.content).hexdigest()
        if digest != self.metadata.sha256:
            raise ValueError("source content does not match metadata SHA-256")
        if any(
            binding.body_sha256 != digest
            for binding in self.metadata.key_authority_bindings
        ):
            raise ValueError("key authority binding does not match source content SHA-256")

    @classmethod
    def from_bytes(
        cls,
        *,
        uri: str,
        source_type: SourceType,
        provider: str | None,
        binding_scope: BindingScope,
        retrieved_at: datetime,
        content: bytes,
        content_type: str | None,
        parser_profile: str,
        source_created_at: datetime | None = None,
        expires_at: datetime | None = None,
        etag: str | None = None,
        last_modified: str | None = None,
        validation_status: ValidationStatus = ValidationStatus.UNVALIDATED,
        key_authority_bindings: tuple[KeyAuthorityBinding, ...] = (),
        acquisition: SourceAcquisition = SourceAcquisition.UNKNOWN,
    ) -> SourceDocument:
        digest = hashlib.sha256(content).hexdigest()
        metadata = SourceMetadata(
            uri=uri,
            source_type=source_type,
            provider=provider,
            binding_scope=binding_scope,
            retrieved_at=retrieved_at,
            sha256=digest,
            content_type=content_type,
            parser_profile=parser_profile,
            source_created_at=source_created_at,
            expires_at=expires_at,
            etag=etag,
            last_modified=last_modified,
            validation_status=validation_status,
            key_authority_bindings=key_authority_bindings,
            acquisition=acquisition,
        )
        return cls(metadata=metadata, content=bytes(content))
