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

    IETF_DIRECTORY_05 = "ietf-directory-05"
    IETF_CIMD_REGISTRY_03 = "ietf-cimd-registry-03"
    CLOUDFLARE_LEGACY = "cloudflare-legacy"


@dataclass(frozen=True, slots=True)
class SignatureAgentReference:
    label: str | None
    uri: str
    card_type: str | None = None
    legacy: bool = False


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
        profile: SignatureAgentProfile = SignatureAgentProfile.IETF_DIRECTORY_05,
    ) -> None:
        self._profile = profile

    def parse(self, raw: str) -> tuple[SignatureAgentReference, ...]:
        if not raw.strip():
            raise SignatureAgentFormatError("Signature-Agent must not be empty")
        structured_fields = structured_fields_module()

        if self._profile is SignatureAgentProfile.CLOUDFLARE_LEGACY:
            return (self._parse_legacy(structured_fields, raw),)
        return self._parse_dictionary(structured_fields, raw)

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
            card_type = str(raw_type).casefold() if raw_type is not None else None
            if (
                self._profile is SignatureAgentProfile.IETF_CIMD_REGISTRY_03
                and card_type != "cimd"
            ):
                raise SignatureAgentFormatError(
                    "CIMD Signature-Agent dictionary members must declare type=cimd"
                )
            references.append(
                SignatureAgentReference(
                    label=str(label),
                    uri=value,
                    card_type=card_type,
                    legacy=False,
                )
            )
        if not references:
            raise SignatureAgentFormatError("Signature-Agent dictionary must not be empty")
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
        return SignatureAgentReference(label=None, uri=value, legacy=True)
