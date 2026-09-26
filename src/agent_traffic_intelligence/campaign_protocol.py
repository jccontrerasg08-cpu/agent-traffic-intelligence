"""Compatibility facade for controlled-campaign planning.

New code should import from :mod:`agent_traffic_intelligence.evaluation.campaign`.
The facade remains stable for existing importers.
"""

from agent_traffic_intelligence.evaluation.campaign import (
    build_navigation_campaign_plan,
    validate_campaign_runtime,
)

__all__ = ["build_navigation_campaign_plan", "validate_campaign_runtime"]
