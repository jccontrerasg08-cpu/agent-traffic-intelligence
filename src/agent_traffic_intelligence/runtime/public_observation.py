"""Privacy-preserving classification of public HTTP capability declarations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

DECLARED_CLIENT_CLASSES = frozenset({"ai", "automation", "bot", "human"})
CLIENT_HINT_FIELDS = ("Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform")
DECLARED_INTERACTION_MODES = frozenset({"mixed", "silent", "text", "tool_call"})


def _header_value(headers: Mapping[str, str], field: str) -> str:
    """Read one HTTP field name without depending on intermediary capitalization."""

    expected = field.casefold()
    for name, value in headers.items():
        if name.casefold() == expected:
            return value
    return ""


def _header_present(headers: Mapping[str, str], field: str) -> bool:
    """Report field presence without returning potentially identifying values."""

    return bool(_header_value(headers, field).strip())


def _declared_client_class(headers: Mapping[str, str]) -> str:
    """Normalize an opt-in category without treating it as verified identity."""

    declared = _header_value(headers, "X-ATI-Client-Class").strip().lower()
    if declared in DECLARED_CLIENT_CLASSES:
        return declared
    return "unspecified"


def _controlled_iteration(headers: Mapping[str, str]) -> str:
    """Classify only a bounded, client-declared experiment iteration."""

    declared = _header_value(headers, "X-ATI-Observation-Iteration").strip()
    if not declared:
        return "not_declared"
    if declared == "1":
        return "first_declared"
    if declared.isdecimal() and int(declared) >= 2:
        return "repeat_declared"
    return "invalid_declaration"


def _declared_interaction_mode(headers: Mapping[str, str]) -> str:
    """Normalize an opt-in interaction category without returning its raw value."""

    declared = _header_value(headers, "X-ATI-Interaction-Mode").strip().lower()
    if declared in DECLARED_INTERACTION_MODES:
        return declared
    return "unspecified"


@dataclass(frozen=True)
class PublicObservation:
    """Derived, response-only capability labels for one public HTTP request."""

    declared_client_class: str
    user_agent_declared: bool
    client_hints_declared: bool
    accept_language_declared: bool
    accept_encoding_declared: bool
    content_type_declared: bool
    content_length_declared: bool
    forwarded_header_state: str
    controlled_iteration: str
    interaction_mode: str
    dns_resolution: str = "not_observable_over_http"
    client_identity: str = "not_verified"
    client_intent: str = "not_observable"

    @classmethod
    def from_headers(cls, headers: Mapping[str, str]) -> PublicObservation:
        """Classify field presence, never field values, remote address, or query text."""

        forwarded = _header_present(headers, "Forwarded") or _header_present(
            headers, "X-Forwarded-For"
        )
        return cls(
            declared_client_class=_declared_client_class(headers),
            user_agent_declared=_header_present(headers, "User-Agent"),
            client_hints_declared=any(
                _header_present(headers, field) for field in CLIENT_HINT_FIELDS
            ),
            accept_language_declared=_header_present(headers, "Accept-Language"),
            accept_encoding_declared=_header_present(headers, "Accept-Encoding"),
            content_type_declared=_header_present(headers, "Content-Type"),
            content_length_declared=_header_present(headers, "Content-Length"),
            controlled_iteration=_controlled_iteration(headers),
            forwarded_header_state=(
                "present_but_untrusted" if forwarded else "not_present"
            ),
            interaction_mode=_declared_interaction_mode(headers),
        )

    def to_dict(self) -> dict[str, bool | str]:
        """Return stable labels suitable for a non-persistent JSON response."""

        return {
            "accept_encoding_declared": self.accept_encoding_declared,
            "accept_language_declared": self.accept_language_declared,
            "client_hints_declared": self.client_hints_declared,
            "client_identity": self.client_identity,
            "client_intent": self.client_intent,
            "controlled_iteration": self.controlled_iteration,
            "content_length_declared": self.content_length_declared,
            "content_type_declared": self.content_type_declared,
            "declared_client_class": self.declared_client_class,
            "dns_resolution": self.dns_resolution,
            "forwarded_header_state": self.forwarded_header_state,
            "interaction_mode": self.interaction_mode,
            "user_agent_declared": self.user_agent_declared,
        }


PUBLIC_CATALOG: dict[str, object] = {
    "access": {"authentication": "not_required", "persistence": "none", "ui": "none"},
    "catalog_version": "2",
    "client_classes": {
        "declared_supported": sorted(DECLARED_CLIENT_CLASSES),
        "interpretation": "declaration_not_verified",
        "unspecified_fallback": "unspecified",
    },
    "dimensions": {
        "accept_encoding": "measurable_presence_only",
        "accept_language": "measurable_presence_only",
        "client_hints": "declared_presence_only",
        "client_identity": "not_verified",
        "client_intent": "not_observable",
        "content_metadata": "measurable_presence_only",
        "controlled_iteration": "declared_experiment_only",
        "dns_resolution": "not_observable_over_http",
        "forwarded_headers": "proxy_trusted_only",
        "interaction_mode": "declared_category_only",
        "user_agent": "declared_presence_only",
    },
    "routes": {
        "/health": "public_service_health",
        "/v1/catalog": "public_capability_catalog",
        "/v1/observe": "public_response_only_observation",
        "/v1/analyze": "authorized_jsonl_analysis_only",
    },
}
