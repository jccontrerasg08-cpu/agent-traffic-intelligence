"""End-to-end observe-only detector orchestration."""

from __future__ import annotations

from agent_traffic_intelligence.features.request import request_features
from agent_traffic_intelligence.features.session import SessionFeatureState
from agent_traffic_intelligence.models import Detection, RequestEvent
from agent_traffic_intelligence.registry import AgentRegistry
from agent_traffic_intelligence.rules.baseline import behavior_evidence, identity_evidence
from agent_traffic_intelligence.scoring import score_evidence

RULESET_VERSION = "2026-08-14-v0"


class Detector:
    """Explainable V0 detector with no enforcement side effects."""

    def __init__(
        self,
        *,
        registry: AgentRegistry | None = None,
        session_state: SessionFeatureState | None = None,
    ) -> None:
        self._registry = registry or AgentRegistry.default()
        self._sessions = session_state or SessionFeatureState()

    def detect(self, event: RequestEvent) -> Detection:
        request = request_features(event)
        session = self._sessions.update(event)
        features: dict[str, float | int | bool | str | None] = {**request, **session}

        entry = self._registry.match_entry(event.user_agent)
        identity = self._registry.match(event.user_agent)
        evidence = tuple(identity_evidence(event, entry) + behavior_evidence(features))
        scores = score_evidence(evidence)

        return Detection(
            request_id=event.request_id,
            automation_score=scores["automation"],
            ai_score=scores["ai"],
            identity_confidence=scores["identity"],
            risk_score=scores["risk"],
            identity=identity,
            evidence=evidence,
            features=features,
            ruleset_version=RULESET_VERSION,
        )
