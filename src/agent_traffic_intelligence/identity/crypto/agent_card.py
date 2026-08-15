"""Signature Agent Card parser for draft-meunier-webbotauth-registry-03."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from agent_traffic_intelligence.identity.crypto.directory import (
    KeyDirectory,
    parse_key_directory,
)


class AgentCardFormatError(ValueError):
    """Raised when a Signature Agent Card violates the pinned profile."""


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _string_tuple(value: Any, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise AgentCardFormatError(f"{name} must be an array of strings")
    return tuple(value)


def _https_uri(value: Any, name: str) -> str | None:
    uri = _string(value)
    if uri is None:
        return None
    parsed = urlsplit(uri)
    if parsed.scheme.casefold() != "https" or not parsed.hostname:
        raise AgentCardFormatError(f"{name} must be an absolute HTTPS URI")
    if parsed.username is not None or parsed.password is not None:
        raise AgentCardFormatError(f"{name} must not contain credentials")
    return uri


@dataclass(frozen=True, slots=True)
class AgentCard:
    client_id: str | None
    client_name: str | None
    client_uri: str | None
    logo_uri: str | None
    contacts: tuple[str, ...]
    jwks_uri: str | None
    inline_jwks: KeyDirectory | None
    expected_user_agent: str | None
    robots_product_token: str | None
    robots_compliance: tuple[str, ...]
    trigger: str | None
    purpose: str | None
    targeted_content: str | None
    rate_control: str | None
    rate_expectation: str | None
    known_urls: tuple[str, ...]
    ips_uri: str | None
    profile: str = "draft-meunier-webbotauth-registry-03"


def parse_agent_card(
    payload: bytes | str | Mapping[str, Any],
    *,
    retrieved_from: str | None = None,
) -> AgentCard:
    if isinstance(payload, bytes):
        try:
            decoded: Any = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentCardFormatError("agent card must be valid UTF-8 JSON") from exc
    elif isinstance(payload, str):
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise AgentCardFormatError("agent card must be valid JSON") from exc
    else:
        decoded = payload
    if not isinstance(decoded, Mapping) or not decoded:
        raise AgentCardFormatError("agent card must be a non-empty JSON object")

    client_id = _https_uri(decoded.get("client_id"), "client_id")
    if retrieved_from is not None:
        if client_id is None:
            raise AgentCardFormatError("a card retrieved through client_id must include client_id")
        if client_id != retrieved_from:
            raise AgentCardFormatError("returned client_id must exactly match the retrieval URL")

    jwks_uri = _https_uri(decoded.get("jwks_uri"), "jwks_uri")
    raw_jwks = decoded.get("jwks")
    if jwks_uri is not None and raw_jwks is not None:
        raise AgentCardFormatError("agent card must not contain both jwks_uri and jwks")
    inline = parse_key_directory(raw_jwks) if raw_jwks is not None else None

    extension = decoded.get("web_bot_auth", {})
    if extension is None:
        extension = {}
    if not isinstance(extension, Mapping):
        raise AgentCardFormatError("web_bot_auth must be a JSON object")
    trigger = _string(extension.get("trigger"))
    if trigger not in (None, "fetcher", "crawler"):
        raise AgentCardFormatError("web_bot_auth.trigger must be fetcher or crawler")

    recognized_top_level = {
        "client_id",
        "client_name",
        "client_uri",
        "logo_uri",
        "contacts",
        "jwks_uri",
        "jwks",
    }
    recognized_web_bot_auth = {
        "expected-user-agent",
        "rfc9309-product-token",
        "rfc9309-compliance",
        "trigger",
        "purpose",
        "targeted-content",
        "rate-control",
        "rate-expectation",
        "known-urls",
        "ips_uri",
    }
    if (
        not recognized_top_level.intersection(decoded)
        and not recognized_web_bot_auth.intersection(extension)
    ):
        raise AgentCardFormatError("agent card must contain at least one recognized parameter")

    return AgentCard(
        client_id=client_id,
        client_name=_string(decoded.get("client_name")),
        client_uri=_string(decoded.get("client_uri")),
        logo_uri=_string(decoded.get("logo_uri")),
        contacts=_string_tuple(decoded.get("contacts"), "contacts"),
        jwks_uri=jwks_uri,
        inline_jwks=inline,
        expected_user_agent=_string(extension.get("expected-user-agent")),
        robots_product_token=_string(extension.get("rfc9309-product-token")),
        robots_compliance=_string_tuple(
            extension.get("rfc9309-compliance"),
            "web_bot_auth.rfc9309-compliance",
        ),
        trigger=trigger,
        purpose=_string(extension.get("purpose")),
        targeted_content=_string(extension.get("targeted-content")),
        rate_control=_string(extension.get("rate-control")),
        rate_expectation=_string(extension.get("rate-expectation")),
        known_urls=_string_tuple(
            extension.get("known-urls"),
            "web_bot_auth.known-urls",
        ),
        ips_uri=_https_uri(extension.get("ips_uri"), "web_bot_auth.ips_uri"),
    )
