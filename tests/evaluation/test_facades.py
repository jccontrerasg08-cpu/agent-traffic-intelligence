"""Regression checks for the evaluation compatibility facades."""

from agent_traffic_intelligence import campaign_protocol, evaluation, pf2_protocol
from agent_traffic_intelligence.evaluation import campaign, metrics
from agent_traffic_intelligence.evaluation.pf2 import protocol


def test_evaluation_package_keeps_the_historical_metric_surface() -> None:
    for name in evaluation.__all__:
        assert getattr(evaluation, name) is getattr(metrics, name)


def test_campaign_protocol_facade_exports_the_canonical_objects() -> None:
    for name in campaign_protocol.__all__:
        assert getattr(campaign_protocol, name) is getattr(campaign, name)


def test_pf2_protocol_facade_exports_the_canonical_objects() -> None:
    for name in pf2_protocol.__all__:
        assert getattr(pf2_protocol, name) is getattr(protocol, name)


def test_pf2_protocol_facade_covers_the_surface_published_on_main() -> None:
    for name in ("PF2ProtocolError", "PF2PreparedDataset", "prepare_pf2_dataset"):
        assert name in pf2_protocol.__all__
