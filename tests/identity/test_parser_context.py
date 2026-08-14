from __future__ import annotations

import json
from io import StringIO

from agent_traffic_intelligence.identity.models import SourceAddressProvenance
from agent_traffic_intelligence.parsers.jsonl import (
    iter_jsonl_with_context,
    normalize_record_with_context,
)


def base_record() -> dict[str, object]:
    return {
        "time_iso8601": "2026-08-14T08:00:00+00:00",
        "remote_addr": "203.0.113.42",
        "scheme": "https",
        "host": "example.com",
        "request_method": "GET",
        "request_uri": "/products?id=secret&utm_source=x",
        "status": 200,
        "body_bytes_sent": 321,
        "server_protocol": "HTTP/2.0",
        "http_user_agent": "ExampleBot/1.0",
        "http_cookie": "session=super-secret",
        "http_authorization": "Bearer should-never-survive",
        "http_signature": "sig1=:secret-material:",
        "http_signature_input": 'sig1=("@authority");created=1',
        "http_signature_agent": "https://agent.example/.well-known/http-message-signatures-directory",
        "http_content_digest": "sha-256=:abc:",
    }


def test_context_keeps_ephemeral_inputs_event_does_not() -> None:
    event, context = normalize_record_with_context(
        base_record(), hash_key=b"key", source="nginx"
    )

    assert context.source_ip == "203.0.113.42"
    assert context.source_address_provenance is SourceAddressProvenance.DIRECT_PEER
    assert context.authority == "example.com"
    assert context.target_uri == "https://example.com/products?id=secret&utm_source=x"
    assert context.signature == "sig1=:secret-material:"
    assert context.covered_headers["content-digest"] == "sha-256=:abc:"

    serialized = json.dumps(event.to_dict())
    assert "203.0.113.42" not in serialized
    assert "secret-material" not in serialized
    assert "utm_source" not in serialized
    assert "Bearer" not in serialized


def test_context_never_copies_authorization_or_cookie_values() -> None:
    _event, context = normalize_record_with_context(base_record(), hash_key=b"key")
    text = repr(dict(context.covered_headers))
    assert "Bearer" not in text
    assert "super-secret" not in text
    assert "authorization" not in context.covered_headers
    assert "cookie" not in context.covered_headers


def test_prehashed_client_has_unknown_source_address() -> None:
    record = base_record()
    record.pop("remote_addr")
    record["client_id"] = "external:pseudonym-1"
    record["http_x_forwarded_for"] = "198.51.100.9"

    _event, context = normalize_record_with_context(record, hash_key=None)
    assert context.source_ip is None
    assert context.source_address_provenance is SourceAddressProvenance.UNKNOWN


def test_iter_with_context_preserves_line_iteration() -> None:
    line = json.dumps(base_record()) + "\n"
    rows = list(iter_jsonl_with_context(StringIO(line), hash_key=b"key", source="nginx"))
    assert len(rows) == 1
    event, context = rows[0]
    assert event.source == "nginx"
    assert context.method == "GET"
