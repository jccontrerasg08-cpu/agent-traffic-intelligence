"""Privacy-safe JSONL access-log parser."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime
from typing import Any, TextIO
from urllib.parse import urlsplit

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.models import SourceAddressProvenance
from agent_traffic_intelligence.models import RequestEvent


class ParseError(ValueError):
    """Raised when an input record cannot be safely normalized."""


DEFAULT_MAX_LINE_CHARACTERS = 1_000_000


def _required(record: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        value = record.get(name)
        if value is not None and value != "":
            return value
    raise ParseError(f"missing required field; expected one of: {', '.join(names)}")


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ParseError("timestamp must be an ISO-8601 string")
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ParseError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ParseError("timestamp must be timezone-aware")
    return parsed


def _safe_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ParseError("request path must be a non-empty string")
    split = urlsplit(value)
    path = split.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    return path


def pseudonymize_client(raw_address: str, hash_key: bytes) -> str:
    """Create a stable keyed pseudonym without retaining the raw network address."""

    if not hash_key:
        raise ParseError("a non-empty hash key is required for raw client addresses")
    digest = hashlib.blake2b(
        raw_address.encode("utf-8"), key=hash_key, digest_size=16, person=b"ati-client-v0"
    ).hexdigest()
    return f"blake2b:{digest}"


def _request_id(
    timestamp: datetime,
    client_id: str,
    method: str,
    path: str,
    status: int,
    *,
    line_number: int | None = None,
) -> str:
    parts: tuple[str, ...] = (
        timestamp.isoformat(),
        client_id,
        method.upper(),
        path,
        str(status),
    )
    if line_number is not None:
        parts = (*parts, str(line_number))
    payload = "\x1f".join(parts).encode("utf-8")
    return "req:" + hashlib.blake2b(payload, digest_size=12, person=b"ati-req-v0").hexdigest()


def _presence_flag(
    record: Mapping[str, Any], *, flag_name: str, header_name: str
) -> bool:
    if flag_name not in record:
        return bool(record.get(header_name))
    value = record[flag_name]
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off", ""}:
            return False
    raise ParseError(f"{flag_name} must be a boolean or a recognized boolean string")


def normalize_record(
    record: Mapping[str, Any],
    *,
    hash_key: bytes | None,
    source: str = "jsonl",
    line_number: int | None = None,
) -> RequestEvent:
    """Normalize an access-log record while discarding sensitive values."""

    timestamp = _parse_timestamp(_required(record, "timestamp", "time_iso8601", "time"))
    method = str(_required(record, "method", "request_method")).upper()
    path = _safe_path(_required(record, "path", "request_uri", "uri"))

    try:
        status = int(_required(record, "status"))
        bytes_sent = int(record.get("bytes_sent", record.get("body_bytes_sent", 0)) or 0)
    except (TypeError, ValueError) as exc:
        raise ParseError("status and bytes fields must be integers") from exc

    supplied_client = record.get("client_id")
    if isinstance(supplied_client, str) and supplied_client:
        client_id = supplied_client
    else:
        raw_address = record.get("remote_addr", record.get("client_ip"))
        if not isinstance(raw_address, str) or not raw_address:
            raise ParseError("record needs client_id or a raw client address")
        if hash_key is None:
            raise ParseError("a hash key is required when a raw client address is present")
        client_id = pseudonymize_client(raw_address, hash_key)

    user_agent_raw = record.get("user_agent", record.get("http_user_agent"))
    user_agent = str(user_agent_raw) if user_agent_raw not in (None, "") else None
    http_version = str(
        record.get("http_version", record.get("server_protocol", "unknown")) or "unknown"
    )
    ja4_raw = record.get("ja4")
    ja4 = str(ja4_raw) if ja4_raw not in (None, "") else None

    request_id_raw = record.get("request_id")
    request_id = (
        str(request_id_raw)
        if request_id_raw not in (None, "")
        else _request_id(
            timestamp,
            client_id,
            method,
            path,
            status,
            line_number=line_number,
        )
    )

    return RequestEvent(
        timestamp=timestamp,
        request_id=request_id,
        client_id=client_id,
        method=method,
        path=path,
        status=status,
        bytes_sent=bytes_sent,
        http_version=http_version,
        user_agent=user_agent,
        has_referer=_presence_flag(
            record,
            flag_name="has_referer",
            header_name="http_referer",
        ),
        has_cookie=_presence_flag(
            record,
            flag_name="has_cookie",
            header_name="http_cookie",
        ),
        has_accept_language=_presence_flag(
            record,
            flag_name="has_accept_language",
            header_name="http_accept_language",
        ),
        ja4=ja4,
        source=source,
    )


def iter_jsonl(
    stream: TextIO | Iterable[str],
    *,
    hash_key: bytes | None,
    source: str = "jsonl",
    max_line_characters: int = DEFAULT_MAX_LINE_CHARACTERS,
) -> Iterator[RequestEvent]:
    """Yield normalized events from line-delimited JSON input."""

    if max_line_characters < 1:
        raise ValueError("max_line_characters must be positive")
    for line_number, raw_line in enumerate(stream, start=1):
        if len(raw_line) > max_line_characters:
            raise ParseError(f"line {line_number}: exceeds configured character limit")
        if not raw_line.strip():
            continue
        try:
            payload = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ParseError(f"line {line_number}: invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ParseError(f"line {line_number}: expected a JSON object")
        try:
            yield normalize_record(
                payload,
                hash_key=hash_key,
                source=source,
                line_number=line_number,
            )
        except ParseError as exc:
            raise ParseError(f"line {line_number}: {exc}") from exc


_SAFE_CONTEXT_HEADERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("content-digest", ("content_digest", "http_content_digest")),
    ("digest", ("digest", "http_digest")),
    ("content-type", ("content_type", "http_content_type")),
    ("date", ("date", "http_date")),
    ("accept", ("accept", "http_accept")),
    ("accept-language", ("accept_language", "http_accept_language")),
    ("user-agent", ("user_agent", "http_user_agent")),
)


def _optional_string(record: Mapping[str, Any], *names: str) -> str | None:
    for name in names:
        value = record.get(name)
        if value not in (None, ""):
            return str(value)
    return None


def _ephemeral_source_address(
    record: Mapping[str, Any],
) -> tuple[str | None, SourceAddressProvenance]:
    raw_address = _optional_string(record, "remote_addr", "client_ip")
    if raw_address is None:
        return None, SourceAddressProvenance.UNKNOWN
    return raw_address, SourceAddressProvenance.DIRECT_PEER


def _ephemeral_target_uri(record: Mapping[str, Any]) -> str | None:
    explicit = _optional_string(record, "target_uri")
    if explicit is not None:
        return explicit
    authority = _optional_string(record, "authority", "host", "http_host", "server_name")
    if authority is None:
        return None
    raw_target = _optional_string(record, "request_uri", "uri", "path")
    if raw_target is None:
        return None
    if raw_target.startswith("http://") or raw_target.startswith("https://"):
        return raw_target
    if not raw_target.startswith("/"):
        raw_target = f"/{raw_target}"
    scheme = _optional_string(record, "scheme") or "https"
    return f"{scheme}://{authority}{raw_target}"


def _safe_ephemeral_headers(record: Mapping[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for canonical_name, aliases in _SAFE_CONTEXT_HEADERS:
        value = _optional_string(record, *aliases)
        if value is not None:
            headers[canonical_name] = value
    return headers


def normalize_record_with_context(
    record: Mapping[str, Any],
    *,
    hash_key: bytes | None,
    source: str = "jsonl",
    line_number: int | None = None,
) -> tuple[RequestEvent, VerificationContext]:
    """Normalize a record and return a separate non-serializable verification context."""

    event = normalize_record(
        record,
        hash_key=hash_key,
        source=source,
        line_number=line_number,
    )
    source_ip, provenance = _ephemeral_source_address(record)
    context = VerificationContext(
        source_ip=source_ip,
        source_address_provenance=provenance,
        authority=_optional_string(record, "authority", "host", "http_host", "server_name"),
        method=event.method,
        target_uri=_ephemeral_target_uri(record),
        signature=_optional_string(record, "signature", "http_signature"),
        signature_input=_optional_string(record, "signature_input", "http_signature_input"),
        signature_agent=_optional_string(record, "signature_agent", "http_signature_agent"),
        covered_headers=_safe_ephemeral_headers(record),
    )
    return event, context


def iter_jsonl_with_context(
    stream: TextIO | Iterable[str],
    *,
    hash_key: bytes | None,
    source: str = "jsonl",
    max_line_characters: int = DEFAULT_MAX_LINE_CHARACTERS,
) -> Iterator[tuple[RequestEvent, VerificationContext]]:
    """Yield normalized events paired with ephemeral verification contexts."""

    if max_line_characters < 1:
        raise ValueError("max_line_characters must be positive")
    for line_number, raw_line in enumerate(stream, start=1):
        if len(raw_line) > max_line_characters:
            raise ParseError(f"line {line_number}: exceeds configured character limit")
        if not raw_line.strip():
            continue
        try:
            payload = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ParseError(f"line {line_number}: invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ParseError(f"line {line_number}: expected a JSON object")
        try:
            yield normalize_record_with_context(
                payload,
                hash_key=hash_key,
                source=source,
                line_number=line_number,
            )
        except ParseError as exc:
            raise ParseError(f"line {line_number}: {exc}") from exc
