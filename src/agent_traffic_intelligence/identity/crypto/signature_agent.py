"""Structured Fields parsing for the Web Bot Auth Signature-Agent header."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol


class SignatureAgentFormatError(ValueError):
    """Raised when Signature-Agent cannot be interpreted safely."""


class SignatureAgentUnavailable(RuntimeError):
    """Raised when optional Structured Fields support is not installed."""


class SignatureAgentProfile(StrEnum):
    """Explicitly selected Signature-Agent interoperability syntax."""

    IETF_HTTPSIG_PROTOCOL_01 = "ietf-httpsig-protocol-01"
    CLOUDFLARE_LEGACY = "cloudflare-legacy"


class SignatureAgentDiscoveryType(StrEnum):
    """Discovery mechanisms defined by the current Web Bot Auth protocol."""

    DIRECTORY = "directory"
    JWKS_URI = "jwks_uri"
    CIMD = "cimd"


@dataclass(frozen=True, slots=True)
class SignatureAgentReference:
    label: str | None
    uri: str
    discovery_type: SignatureAgentDiscoveryType = SignatureAgentDiscoveryType.DIRECTORY
    legacy: bool = False

    @property
    def card_type(self) -> str | None:
        """Compatibility view retained for callers of the earlier experimental API."""

        if self.discovery_type is SignatureAgentDiscoveryType.DIRECTORY:
            return None
        return self.discovery_type.value


class SignatureAgentParser(Protocol):
    def parse(self, raw: str) -> tuple[SignatureAgentReference, ...]: ...


def structured_fields_module() -> Any:
    """Load the Structured Fields implementation supplied by the verification stack."""

    try:
        return importlib.import_module("http_sf.compat")
    except ImportError:
        try:
            return importlib.import_module("http_message_signatures.http_sfv")
        except ImportError as exc:
            raise SignatureAgentUnavailable(
                "optional Structured Fields support is not installed"
            ) from exc


class StructuredFieldSignatureAgentParser:
    """Parse only the syntax selected by an explicit interoperability profile."""

    def __init__(
        self,
        *,
        profile: SignatureAgentProfile = SignatureAgentProfile.IETF_HTTPSIG_PROTOCOL_01,
    ) -> None:
        self._profile = profile

    def parse(self, raw: str) -> tuple[SignatureAgentReference, ...]:
        if not raw.strip():
            raise SignatureAgentFormatError("Signature-Agent must not be empty")
        structured_fields = structured_fields_module()

        if self._profile is SignatureAgentProfile.CLOUDFLARE_LEGACY:
            return (self._parse_legacy(structured_fields, raw),)
        return self._parse_dictionary(structured_fields, raw)

    @staticmethod
    def _discovery_type(raw_type: object | None) -> SignatureAgentDiscoveryType | None:
        if raw_type is None:
            return SignatureAgentDiscoveryType.DIRECTORY
        value = str(raw_type).casefold()
        try:
            return SignatureAgentDiscoveryType(value)
        except ValueError:
            return None

    def _parse_dictionary(
        self,
        structured_fields: Any,
        raw: str,
    ) -> tuple[SignatureAgentReference, ...]:
        dictionary = structured_fields.Dictionary()
        try:
            dictionary.parse(raw.encode("utf-8"))
        except Exception as exc:
            raise SignatureAgentFormatError(
                "Signature-Agent must be a valid dictionary for this interoperability profile"
            ) from exc

        references: list[SignatureAgentReference] = []
        for label, member in dictionary.items():
            value = getattr(member, "value", None)
            if not isinstance(value, str) or not value:
                raise SignatureAgentFormatError(
                    "Signature-Agent dictionary members must be non-empty strings"
                )
            params = getattr(member, "params", {})
            raw_type = params.get("type") if hasattr(params, "get") else None
            discovery_type = self._discovery_type(raw_type)
            if discovery_type is None:
                continue
            references.append(
                SignatureAgentReference(
                    label=str(label),
                    uri=value,
                    discovery_type=discovery_type,
                    legacy=False,
                )
            )
        return tuple(references)

    @staticmethod
    def _parse_legacy(structured_fields: Any, raw: str) -> SignatureAgentReference:
        stripped = raw.strip()
        if not stripped.startswith('"'):
            raise SignatureAgentFormatError(
                "legacy Signature-Agent must use the deployed structured string syntax"
            )
        item = structured_fields.Item()
        try:
            item.parse(stripped.encode("utf-8"))
        except Exception as exc:
            raise SignatureAgentFormatError(
                "legacy Signature-Agent must be a valid structured string"
            ) from exc
        value = getattr(item, "value", None)
        if not isinstance(value, str) or not value:
            raise SignatureAgentFormatError("legacy Signature-Agent must be a string")
        return SignatureAgentReference(
            label=None,
            uri=value,
            discovery_type=SignatureAgentDiscoveryType.DIRECTORY,
            legacy=True,
        )
