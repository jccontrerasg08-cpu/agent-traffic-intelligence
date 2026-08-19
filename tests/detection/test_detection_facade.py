"""Regression checks for the detection compatibility facade."""

from agent_traffic_intelligence import engine
from agent_traffic_intelligence.detection import pipeline


def test_engine_facade_exports_canonical_detection_objects() -> None:
    """Existing engine importers retain the exact canonical implementation."""

    assert engine.Detector is pipeline.Detector
    assert engine.RULESET_VERSION == pipeline.RULESET_VERSION
    assert engine.VERIFIED_RULESET_VERSION == pipeline.VERIFIED_RULESET_VERSION
