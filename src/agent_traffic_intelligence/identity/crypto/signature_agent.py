"""Structured Fields parsing for the Web Bot Auth Signature-Agent header."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Protocol


class SignatureAgentFormatError(ValueError):
    """Raised when Signature-Agent cannot be interpreted safely."""


class SignatureAgentUnavailable(RuntimeError):
    """Raised when optional Structured Fields support is not installed."""


@dataclass(frozen=True, slots=True)
class SignatureAgentReference:
    """One discovery reference from Signature-Agent."""

    label: str | None
    uri: str
    card_type: str | None = None
    legacy: bool = False


class SignatureAgentParser(Protocol):
    def parse(self, raw: str) -> tuple[SignatureAgentReference, ...]: ...


class StructuredFieldSignatureAgentParser:
    """Parse current sf-dictionary and legacy sf-string representations."""

    def parse(self, raw: str) -> tuple[SignatureAgentReference, ...]:
        if not raw.strip():
            raise SignatureAgentFormatError("Signature-Agent must not be empty")
        try:
            compat = importlib.import_module("http_sf.compat")
        except ImportError as exc:
            raise SignatureAgentUnavailable(
                "optional Structured Fields dependency is not installed"
            ) from exc

        dictionary = compat.Dictionary()
        try:
            dictionary.parse(raw.encode("utf-8"))
        except Exception:
            return (self._parse_legacy(compat, raw),)

        references: list[SignatureAgentReference] = []
        for label, member in dictionary.items():
            value = getattr(member, "value", None)
            if not isinstance(value, str) or not value:
                raise SignatureAgentFormatError(
                    "Signature-Agent dictionary members must be non-empty strings"
                )
            params = getattr(member, "params", {})
            raw_type = params.get("type") if hasattr(params, "get") else None
            card_type = str(raw_type) if raw_type is not None else None
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
    def _parse_legacy(compat: object, raw: str) -> SignatureAgentReference:
        item = getattr(compat, "Item")()
        try:
            item.parse(raw.encode("utf-8"))
        except Exception as exc:
            raise SignatureAgentFormatError(
                "Signature-Agent is neither a valid dictionary nor legacy string"
            ) from exc
        value = getattr(item, "value", None)
        if not isinstance(value, str) or not value:
            raise SignatureAgentFormatError("legacy Signature-Agent must be a string")
        return SignatureAgentReference(label=None, uri=value, legacy=True)
