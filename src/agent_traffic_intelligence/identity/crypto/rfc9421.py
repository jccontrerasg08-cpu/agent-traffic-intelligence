"""Optional RFC 9421 verification adapter with ATI-owned result types."""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from types import MappingProxyType
from typing import Any, Protocol, cast

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.models import VerificationOutcome

Scalar = str | int | float | bool | None


class PublicKeyResolver(Protocol):
    def resolve_public_key(self, key_id: str) -> object: ...


@dataclass(frozen=True, slots=True)
class Rfc9421Result:
    outcome: VerificationOutcome
    explanation: str
    label: str | None = None
    algorithm_id: str | None = None
    covered_components: Mapping[str, str] | None = None
    covered_component_names: frozenset[str] = frozenset()
    parameters: Mapping[str, Scalar] | None = None
    nonce: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "covered_components",
            MappingProxyType(dict(self.covered_components or {})),
        )
        object.__setattr__(
            self,
            "parameters",
            MappingProxyType(dict(self.parameters or {})),
        )


@dataclass(slots=True)
class _RequestMessage:
    method: str
    url: str
    headers: dict[str, str]


class Rfc9421Verifier:
    def __init__(self, key_resolver: PublicKeyResolver) -> None:
        self._key_resolver = key_resolver

    def verify(
        self,
        context: VerificationContext,
        *,
        algorithm_id: str,
        expect_tag: str,
        required_components: frozenset[str] = frozenset(),
        max_age_seconds: int = 24 * 60 * 60,
    ) -> Rfc9421Result:
        if not context.signature or not context.signature_input or not context.target_uri:
            return self._result(
                VerificationOutcome.UNAVAILABLE,
                "signature headers and target URI are required",
            )
        if max_age_seconds <= 0:
            return self._result(
                VerificationOutcome.ERROR,
                "maximum signature age must be positive",
            )
        try:
            hms = importlib.import_module("http_message_signatures")
        except ImportError:
            return self._result(
                VerificationOutcome.UNAVAILABLE,
                "optional http-message-signatures dependency is not installed",
            )

        algorithms = getattr(hms, "algorithms", None)
        algorithm = getattr(algorithms, "signature_algorithms", {}).get(algorithm_id)
        if algorithm is None:
            return self._result(
                VerificationOutcome.UNAVAILABLE,
                f"unsupported RFC 9421 algorithm: {algorithm_id}",
            )

        try:
            verifier = hms.HTTPMessageVerifier(
                signature_algorithm=algorithm,
                key_resolver=self._key_resolver,
                component_resolver_class=self._component_resolver(hms),
            )
            verified = verifier.verify(
                self._message(context),
                max_age=timedelta(seconds=max_age_seconds),
                expect_tag=expect_tag,
            )
        except LookupError:
            return self._result(
                VerificationOutcome.UNAVAILABLE,
                "signature key is unavailable",
            )
        except hms.HTTPMessageSignaturesException as exc:
            return self._result(
                VerificationOutcome.MISMATCH,
                f"RFC 9421 verification failed: {exc}",
            )
        except Exception as exc:  # pragma: no cover
            return self._result(
                VerificationOutcome.ERROR,
                f"unexpected RFC 9421 error: {type(exc).__name__}",
            )

        if len(verified) != 1:
            return self._result(
                VerificationOutcome.MISMATCH,
                "verification tag matched an ambiguous number of signatures",
            )
        item = verified[0]
        covered = {
            str(key): str(value)
            for key, value in item.covered_components.items()
        }
        names = frozenset(
            name
            for key in covered
            if (name := self._component_name(key)) != "@signature-params"
        )
        if not required_components.issubset(names):
            return self._result(
                VerificationOutcome.MISMATCH,
                "valid signature did not cover every ATI-required component",
            )
        parameters = {
            str(key): self._scalar(value)
            for key, value in item.parameters.items()
        }
        verified_algorithm = getattr(item.algorithm, "algorithm_id", algorithm_id)
        return Rfc9421Result(
            outcome=VerificationOutcome.PASS,
            explanation="RFC 9421 signature verified",
            label=str(item.label),
            algorithm_id=str(verified_algorithm),
            covered_components=covered,
            covered_component_names=names,
            parameters=parameters,
            nonce=str(item.nonce) if item.nonce is not None else None,
        )

    @staticmethod
    def _component_resolver(hms: Any) -> type:
        try:
            compat = importlib.import_module("http_sf.compat")
        except ImportError:
            return cast(type, hms.HTTPSignatureComponentResolver)
        base = hms.HTTPSignatureComponentResolver

        class AtiComponentResolver(base):  # type: ignore[misc, valid-type]
            def resolve(self, component_node: Any) -> Any:
                component_id = str(component_node.value).casefold()
                key = component_node.params.get("key")
                if component_id == "signature-agent" and key is not None:
                    raw_header = self.headers.get("signature-agent")
                    if raw_header is None:
                        raise hms.HTTPMessageSignaturesException(
                            "covered Signature-Agent header is missing"
                        )
                    dictionary = compat.Dictionary()
                    try:
                        dictionary.parse(str(raw_header).encode("utf-8"))
                    except Exception as exc:
                        raise hms.HTTPMessageSignaturesException(
                            "malformed Signature-Agent dictionary"
                        ) from exc
                    key_text = str(key)
                    if key_text not in dictionary:
                        raise hms.HTTPMessageSignaturesException(
                            "signed Signature-Agent member is missing"
                        )
                    return str(dictionary[key_text])
                return super().resolve(component_node)

        return AtiComponentResolver

    @staticmethod
    def _message(context: VerificationContext) -> _RequestMessage:
        assert context.target_uri is not None
        assert context.signature is not None
        assert context.signature_input is not None
        headers = dict(context.covered_headers)
        headers["Signature"] = context.signature
        headers["Signature-Input"] = context.signature_input
        if context.signature_agent is not None:
            headers["Signature-Agent"] = context.signature_agent
        return _RequestMessage(
            method=context.method,
            url=context.target_uri,
            headers=headers,
        )

    @staticmethod
    def _component_name(serialized: str) -> str:
        value = serialized.strip()
        if value.startswith('"'):
            end = value.find('"', 1)
            if end > 1:
                return value[1:end]
        return value.split(";", 1)[0].strip('"')

    @staticmethod
    def _scalar(value: Any) -> Scalar:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        return str(value)

    @staticmethod
    def _result(
        outcome: VerificationOutcome,
        explanation: str,
    ) -> Rfc9421Result:
        return Rfc9421Result(outcome=outcome, explanation=explanation)
