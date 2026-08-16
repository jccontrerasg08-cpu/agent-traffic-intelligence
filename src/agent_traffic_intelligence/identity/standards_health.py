"""Deterministic health evaluation for pinned Internet-Draft revisions."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

_DATATRACKER_AUTHORITY = "datatracker.ietf.org"
_DATATRACKER_BASE = f"https://{_DATATRACKER_AUTHORITY}"
_DRAFT_PIN_RE = re.compile(r"^(draft-[a-z0-9][a-z0-9-]*?)-(\d{2})$")
_STATE_PATH_RE = re.compile(r"^/api/v1/doc/state/[0-9]+/$")
_BASIC_DRAFT_STATE_TYPE = "/api/v1/doc/statetype/draft/"
_REVIEW_REQUIRED_STATES = frozenset(
    {
        "dead",
        "expired",
        "replaced",
        "replaced by",
        "withdrawn",
    }
)


class DatatrackerPayloadError(ValueError):
    """Datatracker returned metadata outside the constrained expected shape."""


class DraftHealthStatus(StrEnum):
    """Result of comparing one pinned revision with observed metadata."""

    CURRENT = "current"
    REVIEW_REQUIRED = "review_required"


@dataclass(frozen=True, slots=True)
class DraftPin:
    """One exact Internet-Draft revision pinned by ATI."""

    pinned: str
    document_name: str
    revision: str

    @classmethod
    def from_pinned(cls, pinned: str) -> DraftPin:
        match = _DRAFT_PIN_RE.fullmatch(pinned)
        if match is None:
            raise ValueError(
                "pinned Internet-Draft must end in a two-digit revision"
            )
        return cls(
            pinned=pinned,
            document_name=match.group(1),
            revision=match.group(2),
        )


@dataclass(frozen=True, slots=True)
class DraftHealth:
    """Privacy-safe, deterministic comparison result for one draft pin."""

    pin: DraftPin
    observed_revision: str
    status: DraftHealthStatus
    reasons: tuple[str, ...]


def state_api_url(resource_uri: str) -> str:
    """Convert only the exact Datatracker document-state resource path to HTTPS."""

    if _STATE_PATH_RE.fullmatch(resource_uri) is None:
        raise DatatrackerPayloadError(
            "Datatracker state resource URI is outside the allowed document-state API"
        )
    return f"{_DATATRACKER_BASE}{resource_uri}"


def evaluate_datatracker_document(
    pin: DraftPin,
    document_payload: Mapping[str, object],
    *,
    state_payloads: Mapping[str, Mapping[str, object]],
) -> DraftHealth:
    """Compare one Datatracker document payload with a pinned Internet-Draft."""

    observed_name = document_payload.get("name")
    if observed_name != pin.document_name:
        raise DatatrackerPayloadError(
            "Datatracker document name does not match the requested pin"
        )

    observed_revision = document_payload.get("rev")
    if (
        not isinstance(observed_revision, str)
        or re.fullmatch(r"\d{2}", observed_revision) is None
    ):
        raise DatatrackerPayloadError(
            "Datatracker document revision must be a two-digit string"
        )

    states = document_payload.get("states", [])
    if not isinstance(states, list) or not all(isinstance(item, str) for item in states):
        raise DatatrackerPayloadError(
            "Datatracker document states must be a list of resource URIs"
        )

    reasons: list[str] = []
    if observed_revision != pin.revision:
        reasons.append(
            f"pinned revision {pin.revision} differs from observed revision "
            f"{observed_revision}"
        )

    for resource_uri in states:
        assert isinstance(resource_uri, str)
        state_api_url(resource_uri)
        try:
            state_payload = state_payloads[resource_uri]
        except KeyError as exc:
            raise DatatrackerPayloadError(
                "Datatracker state metadata is missing for a declared document state"
            ) from exc
        if state_payload.get("type") != _BASIC_DRAFT_STATE_TYPE:
            continue
        state_name = state_payload.get("name")
        if not isinstance(state_name, str) or not state_name:
            raise DatatrackerPayloadError(
                "Datatracker basic draft state must have a non-empty name"
            )
        if state_name.casefold() in _REVIEW_REQUIRED_STATES:
            reasons.append(f"draft state requires review: {state_name}")

    return DraftHealth(
        pin=pin,
        observed_revision=observed_revision,
        status=(
            DraftHealthStatus.REVIEW_REQUIRED
            if reasons
            else DraftHealthStatus.CURRENT
        ),
        reasons=tuple(reasons),
    )
