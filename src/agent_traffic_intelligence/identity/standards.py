"""Pinned standards profile for experimental Web Bot Auth interoperability."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StandardsProfile:
    """Exact protocol/draft revisions implemented by the verification layer."""

    http_message_signatures: str
    web_bot_auth_protocol: str
    message_signatures_directory: str
    jafar: str
    agent_card: str
    reviewed_on: str

    @property
    def web_bot_auth_architecture(self) -> str:
        """Compatibility alias for the pre-protocol experimental API."""

        return self.web_bot_auth_protocol


DEFAULT_STANDARDS_PROFILE = StandardsProfile(
    http_message_signatures="RFC9421",
    web_bot_auth_protocol="draft-meunier-webbotauth-httpsig-protocol-01",
    message_signatures_directory="draft-meunier-webbotauth-httpsig-directory-00",
    jafar="draft-illyes-webbotauth-jafar-00",
    agent_card="draft-meunier-webbotauth-registry-03",
    reviewed_on="2026-08-14",
)
