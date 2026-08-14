"""Explainable logistic score aggregation."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping

from agent_traffic_intelligence.models import Evidence

DEFAULT_INTERCEPTS: Mapping[str, float] = {
    "automation": -2.2,
    "ai": -3.0,
    "identity": -3.5,
    "risk": -2.4,
}


def sigmoid(value: float) -> float:
    """Numerically stable logistic function."""

    if value >= 0:
        exponent = math.exp(-value)
        return 1.0 / (1.0 + exponent)
    exponent = math.exp(value)
    return exponent / (1.0 + exponent)


def score_evidence(
    evidence: Iterable[Evidence], *, intercepts: Mapping[str, float] = DEFAULT_INTERCEPTS
) -> dict[str, float]:
    """Aggregate independent dimensions in log-odds space."""

    logits = dict(intercepts)
    for item in evidence:
        for dimension, delta in item.score_deltas.items():
            if dimension not in logits:
                continue
            logits[dimension] += float(delta) * item.strength
    return {dimension: sigmoid(value) for dimension, value in logits.items()}
