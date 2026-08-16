from __future__ import annotations

import json
from io import StringIO

import pytest

from agent_traffic_intelligence.parsers.jsonl import ParseError, iter_jsonl, normalize_record


def base_record() -> dict[str, object]:
    return {
        "time_iso8601": "2026-08-14T08:00:00+00:00",
        "remote_addr": "203.0.113.42",
        "request_method": "GET",
        "request_uri": "/products?id=secret&utm_source=x",
        "status": 200,
        "body_bytes_sent": 321,
        "server_protocol": "HTTP/2.0",
        "http_user_agent": "Mozilla/5.0",
        "http_referer": "https://example.com/private?q=x",
        "http_cookie": "session=super-secret",
        "http_accept_language": "en-US",
        "http_authorization": "Bearer should-never-survive",
    }


def test_normalizer_hashes_raw_ip_and_strips_query() -> None:
    event = normalize_record(base_record(), hash_key=b"unit-test-key", source="nginx")

    assert event.client_id.startswith("blake2b:")
    assert "203.0.113.42" not in event.client_id
    assert event.path == "/products"
    assert event.has_cookie is True
    assert event.has_referer is True
    assert event.has_accept_language is True
    assert event.user_agent == "Mozilla/5.0"

    serialized = json.dumps(event.to_dict())
    assert "secret" not in serialized
    assert "203.0.113.42" not in serialized
    assert "utm_source" not in serialized
    assert "Bearer" not in serialized


def test_normalizer_requires_key_when_raw_ip_is_present() -> None:
    with pytest.raises(ParseError, match="hash key"):
        normalize_record(base_record(), hash_key=None)


def test_normalizer_accepts_prehashed_client_id_without_key() -> None:
    record = base_record()
    record.pop("remote_addr")
    record["client_id"] = "external:pseudonym-1"

    event = normalize_record(record, hash_key=None)
    assert event.client_id == "external:pseudonym-1"


def test_iter_jsonl_reports_line_number_for_malformed_json() -> None:
    stream = StringIO(f"{json.dumps(base_record())}\nnot-json\n")

    iterator = iter_jsonl(stream, hash_key=b"key")
    next(iterator)
    with pytest.raises(ParseError, match="line 2"):
        next(iterator)


def test_normalizer_rejects_naive_timestamp() -> None:
    record = base_record()
    record["time_iso8601"] = "2026-08-14T08:00:00"

    with pytest.raises(ParseError, match="timezone-aware"):
        normalize_record(record, hash_key=b"key")


def test_normalizer_parses_explicit_boolean_strings() -> None:
    record = base_record()
    record["has_cookie"] = "false"
    record["has_referer"] = "1"
    record["has_accept_language"] = "off"

    event = normalize_record(record, hash_key=b"key")

    assert event.has_cookie is False
    assert event.has_referer is True
    assert event.has_accept_language is False


def test_normalizer_rejects_unknown_boolean_strings() -> None:
    record = base_record()
    record["has_cookie"] = "sometimes"

    with pytest.raises(ParseError, match="has_cookie"):
        normalize_record(record, hash_key=b"key")


def test_iter_jsonl_uses_line_number_to_disambiguate_generated_request_ids() -> None:
    record = base_record()
    record.pop("remote_addr")
    record["client_id"] = "external:pseudonym-1"
    serialized = json.dumps(record)

    events = tuple(iter_jsonl(StringIO(f"{serialized}\n{serialized}\n"), hash_key=None))

    assert len(events) == 2
    assert events[0].request_id != events[1].request_id


def test_iter_jsonl_rejects_lines_over_the_configured_limit() -> None:
    with pytest.raises(ParseError, match="character limit"):
        tuple(iter_jsonl(StringIO("{}\n"), hash_key=None, max_line_characters=1))
