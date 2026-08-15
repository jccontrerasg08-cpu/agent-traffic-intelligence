"""RFC 9421 response-message adapters for request-bound components."""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, cast
from urllib.parse import urlsplit


class Rfc9421ResponseUnavailable(RuntimeError):
    """Raised when optional HTTP Message Signatures support is unavailable."""


@dataclass(frozen=True, slots=True)
class ResponseRequest:
    """Minimal originating-request context required by RFC 9421 ``req``."""

    method: str
    url: str
    headers: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


@dataclass(frozen=True, slots=True)
class ResponseMessage:
    """Minimal HTTP response shape consumed by http-message-signatures."""

    status_code: int
    url: str
    headers: Mapping[str, str]
    request: ResponseRequest

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


def _upstream_component_resolver() -> type[Any]:
    try:
        module = importlib.import_module("http_message_signatures.resolvers")
    except ImportError as exc:
        raise Rfc9421ResponseUnavailable(
            "optional HTTP Message Signatures support is not installed"
        ) from exc
    return cast(type[Any], module.HTTPSignatureComponentResolver)


def response_component_resolver_class() -> type[Any]:
    """Return an upstream-compatible resolver that implements RFC 9421 ``req``.

    The upstream resolver already handles normal response components and
    cryptographic signature-base construction. ATI only supplies the missing
    request-context switch for derived request components in a response.
    """

    base = _upstream_component_resolver()

    class ResponseComponentResolver(base):  # type: ignore[misc, valid-type]
        def get_authority(self, *, req: bool = False) -> str:
            if not req:
                return str(super().get_authority())
            request = getattr(self.message, "request", None)
            if request is None:
                raise ValueError("response is missing its originating request context")
            authority = urlsplit(str(request.url)).netloc.lower()
            if not authority:
                raise ValueError("originating request URL is missing an authority")
            return authority

    return ResponseComponentResolver
