"""Contract tests proving research routes remain gated and inert by default."""

from __future__ import annotations

import pytest

from agent_traffic_intelligence.research import (
    ResearchCase,
    ResearchReadiness,
    ResearchTrack,
)


def test_documented_research_case_requires_explicit_data_and_metrics() -> None:
    case = ResearchCase(
        track=ResearchTrack.NETWORK_FINGERPRINT,
        readiness=ResearchReadiness.DOCUMENTED,
        owner="research-owner",
        authorization_reference=None,
        data_categories=("ja4", "pseudonymous_client_id"),
        retention_policy="ephemeral controlled fixture only",
        evaluation_metrics=("coverage", "false_positive_rate"),
    )

    assert case.readiness is ResearchReadiness.DOCUMENTED


def test_ready_research_case_requires_authorization_reference() -> None:
    with pytest.raises(ValueError, match="authorization reference"):
        ResearchCase(
            track=ResearchTrack.BROWSER_LAB,
            readiness=ResearchReadiness.READY_FOR_REVIEW,
            owner="research-owner",
            authorization_reference=None,
            data_categories=("browser_lab_metadata",),
            retention_policy="approved retention policy",
            evaluation_metrics=("coverage",),
        )
