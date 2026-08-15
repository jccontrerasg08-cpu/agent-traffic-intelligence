"""Strict retrieval of CIMD client metadata documents for Web Bot Auth."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from agent_traffic_intelligence.identity.crypto.agent_card import (
    AgentCard,
    AgentCardFormatError,
    parse_agent_card,
)
from agent_traffic_intelligence.identity.crypto.jwk_set import JwkSetFormatError
from agent_traffic_intelligence.identity.sources.fetcher import (
    AddressResolver,
    FetchProtocolError,
    FetchSecurityError,
    FetchTransport,
    SafeFetcher,
)


class ClientCardFetchStatus(StrEnum):
    """Privacy-safe outcome for one client metadata document retrieval."""

    SUCCESS = "success"
    UNAVAILABLE = "unavailable"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class ClientCardFetchResult:
    """Result without response bodies, source IPs, or sensitive request details."""

    status: ClientCardFetchStatus
    card: AgentCard | None
    explanation: str


class ClientCardFetcher:
    """Fetch a client_id document using CIMD's stricter retrieval policy."""

    def __init__(
        self,
        *,
        resolver: AddressResolver | None = None,
        transport: FetchTransport | None = None,
        max_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        self._fetcher = SafeFetcher(
            resolver=resolver,
            transport=transport,
            max_bytes=max_bytes,
            max_redirects=0,
        )

    def fetch(self, client_id: str) -> ClientCardFetchResult:
        """Fetch exactly one HTTPS client_id URL without following redirects."""

        try:
            fetched = self._fetcher.fetch(client_id)
        except FetchSecurityError:
            return ClientCardFetchResult(
                status=ClientCardFetchStatus.INVALID,
                card=None,
                explanation="client_id rejected by source policy",
            )
        except FetchProtocolError as exc:
            explanation = (
                "client card redirect rejected"
                if "redirect" in str(exc).casefold()
                else "client card source unavailable"
            )
            return ClientCardFetchResult(
                status=ClientCardFetchStatus.UNAVAILABLE,
                card=None,
                explanation=explanation,
            )

        if fetched.status != 200 or fetched.body is None:
            return ClientCardFetchResult(
                status=ClientCardFetchStatus.UNAVAILABLE,
                card=None,
                explanation="client card response must be HTTP 200",
            )

        try:
            card = parse_agent_card(fetched.body, retrieved_from=client_id)
        except (AgentCardFormatError, JwkSetFormatError):
            return ClientCardFetchResult(
                status=ClientCardFetchStatus.INVALID,
                card=None,
                explanation="client card client_id or metadata is invalid",
            )

        return ClientCardFetchResult(
            status=ClientCardFetchStatus.SUCCESS,
            card=card,
            explanation="client card fetched and validated",
        )
