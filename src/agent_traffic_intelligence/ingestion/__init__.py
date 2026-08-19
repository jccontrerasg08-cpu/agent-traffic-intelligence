"""Canonical privacy-safe ingestion interfaces for normalized access events."""

from agent_traffic_intelligence.ingestion.jsonl import (
    DEFAULT_MAX_LINE_CHARACTERS,
    ParseError,
    iter_jsonl,
    iter_jsonl_with_context,
    normalize_record,
    normalize_record_with_context,
    pseudonymize_client,
)

__all__ = [
    "DEFAULT_MAX_LINE_CHARACTERS",
    "ParseError",
    "iter_jsonl",
    "iter_jsonl_with_context",
    "normalize_record",
    "normalize_record_with_context",
    "pseudonymize_client",
]
