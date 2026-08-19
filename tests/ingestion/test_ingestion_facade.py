"""Regression checks for the ingestion compatibility facade."""

from agent_traffic_intelligence import ingestion
from agent_traffic_intelligence.parsers import jsonl


def test_parser_facade_exports_canonical_ingestion_objects() -> None:
    """Existing parser importers retain the exact canonical implementation."""

    assert jsonl.ParseError is ingestion.ParseError
    assert jsonl.iter_jsonl is ingestion.iter_jsonl
    assert jsonl.normalize_record is ingestion.normalize_record
