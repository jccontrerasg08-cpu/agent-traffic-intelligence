"""Compatibility facade for the ATI-PF-2 session protocol.

New code should import from :mod:`agent_traffic_intelligence.evaluation.pf2`.
The facade remains stable for existing importers.
"""

from agent_traffic_intelligence.evaluation.pf2.protocol import (
    PF2_CATALOGUE_VERSION,
    PF2_FEATURE_FAMILIES,
    PF2_ROUTE_CATEGORIES,
    PF2_TARGET_NAME,
    PF2PreparedDataset,
    PF2ProtocolError,
    is_pf2_session_id,
    pf2_feature_names,
    prepare_pf2_dataset,
)

__all__ = [
    "PF2_CATALOGUE_VERSION",
    "PF2_FEATURE_FAMILIES",
    "PF2_ROUTE_CATEGORIES",
    "PF2_TARGET_NAME",
    "PF2PreparedDataset",
    "PF2ProtocolError",
    "is_pf2_session_id",
    "pf2_feature_names",
    "prepare_pf2_dataset",
]
