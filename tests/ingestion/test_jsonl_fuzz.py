"""Property-based regression checks for untrusted JSONL input."""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agent_traffic_intelligence.ingestion.jsonl import ParseError, iter_jsonl

_BASE_RECORD = {
    "timestamp": "2026-08-20T00:00:00Z",
    "method": "GET",
    "path": "/observe",
    "status": 200,
}


@settings(max_examples=20, deadline=None)
@given(
    prefix=st.text(alphabet="abc", max_size=4),
    suffix=st.text(alphabet="xyz", max_size=4),
    surrogate=st.sampled_from(["\ud800", "\udfff"]),
)
def test_iter_jsonl_converts_non_utf8_client_addresses_to_parse_errors(
    prefix: str, suffix: str, surrogate: str
) -> None:
    """Untrusted JSON escapes must not leak encoding exceptions from ingestion."""

    line = json.dumps({**_BASE_RECORD, "remote_addr": f"{prefix}{surrogate}{suffix}"})

    with pytest.raises(ParseError):
        list(iter_jsonl([line], hash_key=b"fuzz-key"))


@settings(max_examples=10, deadline=None)
@given(status=st.sampled_from([float("inf"), float("-inf"), float("nan")]))
def test_iter_jsonl_converts_non_finite_status_to_parse_errors(status: float) -> None:
    """Non-finite JSON numbers must not leak conversion exceptions from ingestion."""

    line = json.dumps({**_BASE_RECORD, "remote_addr": "203.0.113.10", "status": status})

    with pytest.raises(ParseError):
        list(iter_jsonl([line], hash_key=b"fuzz-key"))
