"""Deterministic health evaluation for pinned Internet-Draft revisions."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from agent_traffic_intelligence.identity.standards import (
    DEFAULT_STANDARDS_PROFILE,
    StandardsProfile,
)

_DATATRACKER_AUTHORITY = "datatracker.ietf.org"
_DATATRACKER_BASE = f"https://{_DATATRACKER_AUTHORITY}"
_DRAFT_PIN_RE = re.compile(r"^(draft-[a-z0-9][a-z0-9-]*?)-(\d{2})$")
_DOCUMENT_PATH_RE = re.compile(r"^/api/v1/doc/document/draft-[a-z0-9][a-z0-9-]*/$")
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
_USER_AGENT = "agent-traffic-intelligence/0.1 standards-health"


class DatatrackerPayloadError(ValueError):
    """Datatracker returned metadata outside the constrained expected shape."""


class StandardsHealthOperationalError(RuntimeError):
    """The standards-health check could not safely obtain upstream metadata."""


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


@dataclass(frozen=True, slots=True)
class StandardsHealthReport:
    """Aggregate result for all pinned Internet-Drafts."""

    drafts: tuple[DraftHealth, ...]

    @property
    def review_required(self) -> bool:
        return any(
            draft.status is DraftHealthStatus.REVIEW_REQUIRED for draft in self.drafts
        )


@dataclass(frozen=True, slots=True)
class DatatrackerHttpResponse:
    """Small transport-neutral HTTP response used by standards health."""

    status: int
    final_url: str
    content_type: str | None
    body: bytes


class DatatrackerTransport(Protocol):
    """Injected transport boundary so deterministic tests never use the network."""

    def get(
        self,
        url: str,
        *,
        timeout_seconds: float,
        max_body_bytes: int,
    ) -> DatatrackerHttpResponse: ...


class DatatrackerNoRedirectHandler(HTTPRedirectHandler):
    """Prevent urllib from following any HTTP redirect."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class UrllibDatatrackerTransport:
    """Minimal stdlib HTTPS transport for explicit standards-health checks."""

    def __init__(self, *, opener: Any | None = None) -> None:
        self._opener = opener or build_opener(
            ProxyHandler({}),
            DatatrackerNoRedirectHandler(),
        )

    def get(
        self,
        url: str,
        *,
        timeout_seconds: float,
        max_body_bytes: int,
    ) -> DatatrackerHttpResponse:
        request = Request(
            url,
            method="GET",
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "User-Agent": _USER_AGENT,
            },
        )
        try:
            with self._opener.open(request, timeout=timeout_seconds) as response:
                return self._response_from_handle(response, max_body_bytes=max_body_bytes)
        except HTTPError as exc:
            return self._response_from_handle(exc, max_body_bytes=max_body_bytes)
        except (URLError, TimeoutError, OSError) as exc:
            raise StandardsHealthOperationalError(
                f"Datatracker transport failed: {type(exc).__name__}"
            ) from exc

    @staticmethod
    def _response_from_handle(
        response: Any,
        *,
        max_body_bytes: int,
    ) -> DatatrackerHttpResponse:
        body = bytes(response.read(max_body_bytes + 1))
        headers = getattr(response, "headers", None)
        content_type: str | None = None
        if headers is not None:
            value = headers.get("Content-Type")
            if value is not None:
                content_type = str(value)
        status = getattr(response, "status", None)
        if status is None:
            status = response.getcode()
        return DatatrackerHttpResponse(
            status=int(status),
            final_url=str(response.geturl()),
            content_type=content_type,
            body=body,
        )


class DatatrackerJsonClient:
    """Validate bounded JSON responses from the constrained Datatracker API."""

    def __init__(
        self,
        *,
        transport: DatatrackerTransport,
        timeout_seconds: float = 5.0,
        max_body_bytes: int = 256 * 1024,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive")
        self._transport = transport
        self._timeout_seconds = timeout_seconds
        self._max_body_bytes = max_body_bytes

    def fetch_json(self, url: str) -> dict[str, object]:
        self._validate_url(url)
        try:
            response = self._transport.get(
                url,
                timeout_seconds=self._timeout_seconds,
                max_body_bytes=self._max_body_bytes,
            )
        except StandardsHealthOperationalError:
            raise
        except Exception as exc:
            raise StandardsHealthOperationalError(
                f"Datatracker transport failed: {type(exc).__name__}"
            ) from exc

        if response.status != 200:
            raise StandardsHealthOperationalError(
                f"Datatracker returned unexpected HTTP status {response.status}"
            )
        if response.final_url != url:
            raise StandardsHealthOperationalError(
                "Datatracker redirect is not allowed for standards health"
            )
        media_type = (response.content_type or "").split(";", 1)[0].strip().casefold()
        if media_type != "application/json":
            raise StandardsHealthOperationalError(
                "Datatracker response content type must be application/json"
            )
        if len(response.body) > self._max_body_bytes:
            raise StandardsHealthOperationalError(
                "Datatracker response exceeds the configured body limit"
            )
        try:
            payload = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DatatrackerPayloadError(
                "Datatracker response is not valid UTF-8 JSON"
            ) from exc
        if not isinstance(payload, dict) or not all(
            isinstance(key, str) for key in payload
        ):
            raise DatatrackerPayloadError(
                "Datatracker response must be a JSON object with string keys"
            )
        return payload

    @staticmethod
    def _validate_url(url: str) -> None:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as exc:
            raise StandardsHealthOperationalError(
                "URL is outside the allowed Datatracker API"
            ) from exc
        valid_path = bool(
            _DOCUMENT_PATH_RE.fullmatch(parsed.path)
            or _STATE_PATH_RE.fullmatch(parsed.path)
        )
        if not (
            parsed.scheme == "https"
            and parsed.hostname == _DATATRACKER_AUTHORITY
            and port is None
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
            and valid_path
        ):
            raise StandardsHealthOperationalError(
                "URL is outside the allowed Datatracker API"
            )


def default_draft_pins(
    profile: StandardsProfile = DEFAULT_STANDARDS_PROFILE,
) -> tuple[DraftPin, ...]:
    """Return only the revisioned Internet-Drafts implemented by ATI."""

    return tuple(
        DraftPin.from_pinned(value)
        for value in (
            profile.web_bot_auth_protocol,
            profile.message_signatures_directory,
            profile.jafar,
            profile.agent_card,
        )
    )


def document_api_url(pin: DraftPin) -> str:
    """Build the fixed Datatracker document-object URL for one validated pin."""

    return f"{_DATATRACKER_BASE}/api/v1/doc/document/{pin.document_name}/"


def state_api_url(resource_uri: str) -> str:
    """Convert only the exact Datatracker document-state resource path to HTTPS."""

    if _STATE_PATH_RE.fullmatch(resource_uri) is None:
        raise DatatrackerPayloadError(
            "Datatracker state resource URI is outside the allowed document-state API"
        )
    return f"{_DATATRACKER_BASE}{resource_uri}"


def check_pinned_drafts(
    *,
    client: DatatrackerJsonClient,
    pins: tuple[DraftPin, ...] | None = None,
) -> StandardsHealthReport:
    """Fetch current metadata and report drift without mutating any ATI pin."""

    results: list[DraftHealth] = []
    for pin in pins or default_draft_pins():
        document_payload = client.fetch_json(document_api_url(pin))
        state_resources = _state_resources(document_payload)
        state_payloads = {
            resource_uri: client.fetch_json(state_api_url(resource_uri))
            for resource_uri in state_resources
        }
        results.append(
            evaluate_datatracker_document(
                pin,
                document_payload,
                state_payloads=state_payloads,
            )
        )
    return StandardsHealthReport(drafts=tuple(results))


def _state_resources(document_payload: Mapping[str, object]) -> tuple[str, ...]:
    states = document_payload.get("states", [])
    if not isinstance(states, list) or not all(isinstance(item, str) for item in states):
        raise DatatrackerPayloadError(
            "Datatracker document states must be a list of resource URIs"
        )
    resources = tuple(states)
    for resource_uri in resources:
        state_api_url(resource_uri)
    return resources


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
