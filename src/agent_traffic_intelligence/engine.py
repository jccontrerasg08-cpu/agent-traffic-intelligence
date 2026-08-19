"""Compatibility facade for the canonical detection pipeline.

New code should import from :mod:`agent_traffic_intelligence.detection`.
The facade remains intentionally stable for existing CLI, service, and library callers.
"""

from agent_traffic_intelligence.detection import (
    RULESET_VERSION,
    VERIFIED_RULESET_VERSION,
    Detector,
)

__all__ = ["RULESET_VERSION", "VERIFIED_RULESET_VERSION", "Detector"]
