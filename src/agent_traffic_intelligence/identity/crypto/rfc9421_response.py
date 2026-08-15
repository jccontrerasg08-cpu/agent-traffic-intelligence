"""RFC 9421 response-message adapters for request-bound components."""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from types import MappingProxyType
from typing import Any, cast
from urllib.parse import urlsplit

from agent_traffic_intelligence.identity.crypto.rfc9421 import (
    PublicKeyResolver,
    Rfc9421Result,
    Rfc9421Verifier,
)
from agent_traffic_intelligence.identity.models import VerificationOutcome


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


class Rfc9421ResponseVerifier:
    """Verify RFC 9421 response signatures while preserving request context."""

    def __init__(self, key_resolver: PublicKeyResolver) -> None:
        self._key_resolver = key_resolver

    def verify(
        self,
        message: ResponseMessage,
        *,
        algorithm_id: str,
        expect_tag: str,
        required_components: frozenset[str] = frozenset(),
        max_age_seconds: int = 24 * 60 * 60,
    ) -> Rfc9421Result:
        if max_age_seconds <= 0:
            return Rfc9421Verifier._result(
                VerificationOutcome.ERROR,
                "maximum signature age must be positive",
            )
        if not self._header(message.headers, "signature") or not self._header(
            message.headers, "signature-input"
        ):
            return Rfc9421Verifier._result(
                VerificationOutcome.UNAVAILABLE,
                "response Signature and Signature-Input headers are required",
            )
        try:
            hms = importlib.import_module("http_message_signatures")
        except ImportError:
            return Rfc9421Verifier._result(
                VerificationOutcome.UNAVAILABLE,
                "optional http-message-signatures dependency is not installed",
            )

        algorithms = getattr(hms, "algorithms", None)
        algorithm = getattr(algorithms, "signature_algorithms", {}).get(algorithm_id)
        if algorithm is None:
            return Rfc9421Verifier._result(
                VerificationOutcome.UNAVAILABLE,
                f"unsupported RFC 9421 algorithm: {algorithm_id}",
            )

        try:
            verifier = hms.HTTPMessageVerifier(
                signature_algorithm=algorithm,
                key_resolver=self._key_resolver,
                component_resolver_class=response_component_resolver_class(),
            )
            verified = verifier.verify(
                message,
                max_age=timedelta(seconds=max_age_seconds),
                expect_tag=expect_tag,
            )
        except LookupError:
            return Rfc9421Verifier._result(
                VerificationOutcome.UNAVAILABLE,
                "response signature key is unavailable",
            )
        except hms.HTTPMessageSignaturesException as exc:
            return Rfc9421Verifier._result(
                VerificationOutcome.MISMATCH,
                f"RFC 9421 response verification failed: {exc}",
            )
        except Exception as exc:  # pragma: no cover
            return Rfc9421Verifier._result(
                VerificationOutcome.ERROR,
                f"unexpected RFC 9421 response error: {type(exc).__name__}",
            )

        if len(verified) != 1:
            return Rfc9421Verifier._result(
                VerificationOutcome.MISMATCH,
                "verification tag matched an ambiguous number of response signatures",
            )
        item = verified[0]
        covered = {str(key): str(value) for key, value in item.covered_components.items()}
        names = frozenset(
            name
            for key in covered
            if (name := Rfc9421Verifier._component_name(key)) != "@signature-params"
        )
        if not required_components.issubset(names):
            return Rfc9421Verifier._result(
                VerificationOutcome.MISMATCH,
                "valid response signature did not cover every ATI-required component",
            )
        parameters = {
            str(key): Rfc9421Verifier._scalar(value)
            for key, value in item.parameters.items()
        }
        nonce_value = parameters.get("nonce")
        verified_algorithm = getattr(item.algorithm, "algorithm_id", algorithm_id)
        return Rfc9421Result(
            outcome=VerificationOutcome.PASS,
            explanation="RFC 9421 response signature verified",
            label=str(item.label),
            algorithm_id=str(verified_algorithm),
            covered_components=covered,
            covered_component_names=names,
            parameters=parameters,
            nonce=str(nonce_value) if nonce_value is not None else None,
        )

    @staticmethod
    def _header(headers: Mapping[str, str], name: str) -> str | None:
        target = name.casefold()
        for key, value in headers.items():
            if key.casefold() == target:
                return value
        return None
