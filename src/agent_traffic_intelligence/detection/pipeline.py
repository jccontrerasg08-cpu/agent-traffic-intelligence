"""End-to-end observe-only detector orchestration."""

from __future__ import annotations

from dataclasses import replace

from agent_traffic_intelligence.features.request import request_features
from agent_traffic_intelligence.features.session import SessionFeatureState
from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.manager import VerificationManager
from agent_traffic_intelligence.identity.models import VerificationResolution
from agent_traffic_intelligence.models import Detection, Evidence, RequestEvent, VerificationState
from agent_traffic_intelligence.registry import AgentRegistry
from agent_traffic_intelligence.rules.baseline import behavior_evidence, identity_evidence
from agent_traffic_intelligence.scoring import score_evidence

RULESET_VERSION = "2026-08-14-v0"
VERIFIED_RULESET_VERSION = "2026-08-14-v1"


def _resolution_score_evidence(resolution: VerificationResolution) -> Evidence | None:
    """Convert the categorical identity resolution into one calibrated score contribution."""

    if resolution.state is VerificationState.VERIFIED:
        code = "verified-agent-identity"
        description = "Authority-bound verification confirms the exact claimed agent identity."
        delta = 5.5
    elif resolution.provider_verified:
        code = "verified-provider-identity"
        description = "Verification confirms the claimed provider but not the exact agent."
        delta = 2.0
    elif resolution.state is VerificationState.FAILED:
        code = "failed-identity-verification"
        description = "Applicable authoritative identity evidence contradicts the claim."
        delta = -2.0
    elif resolution.state is VerificationState.CONFLICTED:
        code = "conflicted-identity-verification"
        description = "Strong identity evidence conflicts and cannot be safely reconciled."
        delta = -1.0
    else:
        return None
    return Evidence(
        code=code,
        source="identity-verification",
        description=description,
        strength=1.0,
        score_deltas={"identity": delta},
    )


class Detector:
    """Explainable observe-only detector with optional V1 identity verification."""

    def __init__(
        self,
        *,
        registry: AgentRegistry | None = None,
        session_state: SessionFeatureState | None = None,
        verification_manager: VerificationManager | None = None,
    ) -> None:
        self._registry = registry or AgentRegistry.default()
        self._sessions = session_state or SessionFeatureState()
        self._verification_manager = verification_manager

    def session_resource_metrics(self) -> dict[str, int]:
        """Return bounded session-state metrics for an analyzer invocation."""

        return self._sessions.resource_metrics()

    def detect(
        self,
        event: RequestEvent,
        verification_context: VerificationContext | None = None,
    ) -> Detection:
        request = request_features(event)
        session = self._sessions.update(event)
        features: dict[str, float | int | bool | str | None] = {**request, **session}

        entry = self._registry.match_entry(event.user_agent)
        identity = self._registry.match(event.user_agent)
        evidence = tuple(identity_evidence(event, entry) + behavior_evidence(features))
        verification: VerificationResolution | None = None

        if (
            identity is not None
            and verification_context is not None
            and self._verification_manager is not None
        ):
            verification = self._verification_manager.verify(
                event=event,
                context=verification_context,
                claim=identity,
            )
            identity = replace(identity, verification_state=verification.state)
            resolution_evidence = _resolution_score_evidence(verification)
            if resolution_evidence is not None:
                evidence = (*evidence, resolution_evidence)

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
            ruleset_version=(
                VERIFIED_RULESET_VERSION if verification is not None else RULESET_VERSION
            ),
            verification=verification,
        )
