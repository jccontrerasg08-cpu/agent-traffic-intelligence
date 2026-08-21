"""Privacy-safe planning and validation helpers for controlled navigation campaigns."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from agent_traffic_intelligence.evaluation import EvaluationError

_CAMPAIGN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SESSION_ID = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_SPLIT_REQUIREMENTS = [
    "grouped_session_client",
    "temporal_holdout",
    "unseen_family_holdout",
    "provider_ua_ablation",
]
_PROHIBITED_FIELDS = ["authorization", "body", "cookie", "ip_address", "query_string"]
_NAVIGATION_ROUTES = [
    {"method": "GET", "path": "/lab/start"},
    {"method": "GET", "path": "/lab/page/landing"},
    {"method": "GET", "path": "/lab/assets/site.css"},
    {"method": "GET", "path": "/lab/page/catalog"},
    {"method": "HEAD", "path": "/lab/page/detail"},
    {"method": "GET", "path": "/lab/missing"},
]


def build_navigation_campaign_plan(
    *,
    campaign_id: str,
    corpus_id: str,
    families: Mapping[str, str],
    sessions_per_family: int,
) -> dict[str, object]:
    """Build a versionable, non-secret plan for controlled navigation sessions."""

    if not _CAMPAIGN_ID.fullmatch(campaign_id):
        raise EvaluationError("campaign_id must be an opaque campaign marker")
    if not corpus_id.strip():
        raise EvaluationError("corpus_id must be non-empty")
    if sessions_per_family < 1:
        raise EvaluationError("sessions_per_family must be positive")
    if not families:
        raise EvaluationError("at least one runtime family is required")

    normalized_families: list[dict[str, str]] = []
    for name, ua_token in families.items():
        if not name.strip() or not ua_token.strip():
            raise EvaluationError("family name and UA token must be non-empty")
        normalized_families.append({"name": name, "ua_token": ua_token})

    return {
        "schema_version": 1,
        "protocol": "session-navigation-v1",
        "campaign_id": campaign_id,
        "corpus_id": corpus_id,
        "families": normalized_families,
        "sessions_per_family": sessions_per_family,
        "routes": _NAVIGATION_ROUTES,
        "prohibited_fields": _PROHIBITED_FIELDS,
        "split_requirements": _SPLIT_REQUIREMENTS,
    }


def validate_campaign_runtime(
    records: Iterable[Mapping[str, Any]],
    *,
    campaign_id: str,
    expected_ua_token: str,
) -> dict[str, int | str]:
    """Summarize session and user-agent compatibility without retaining raw values."""

    if not _CAMPAIGN_ID.fullmatch(campaign_id):
        raise EvaluationError("campaign_id must be an opaque campaign marker")
    if not expected_ua_token.strip():
        raise EvaluationError("expected_ua_token must be non-empty")

    observed = compatible = incompatible = missing_session = 0
    sessions: set[str] = set()
    expected_token = expected_ua_token.casefold()
    for record in records:
        if record.get("ati_campaign_id") != campaign_id:
            continue
        observed += 1
        session_id = record.get("session_id")
        if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
            missing_session += 1
            continue
        sessions.add(session_id)
        user_agent = record.get("http_user_agent")
        if isinstance(user_agent, str) and expected_token in user_agent.casefold():
            compatible += 1
        else:
            incompatible += 1

    return {
        "campaign_id": campaign_id,
        "observed_request_count": observed,
        "observed_session_count": len(sessions),
        "compatible_request_count": compatible,
        "incompatible_request_count": incompatible,
        "missing_session_count": missing_session,
        "status": (
            "ready"
            if observed and not incompatible and not missing_session
            else "review-required"
        ),
    }
