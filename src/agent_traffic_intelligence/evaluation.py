"""Local, privacy-minimized evaluation helpers for labeled detection outputs."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any


class EvaluationError(ValueError):
    """Raised when an evaluation corpus does not meet ATI's minimal contract."""


@dataclass(frozen=True, slots=True)
class AutomationEvaluation:
    """Binary automation-score metrics over a caller-supplied labeled corpus."""

    evaluated_request_count: int
    unlabeled_request_count: int
    unmatched_label_count: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    accuracy: float
    brier_score: float
    threshold: float

    def to_dict(self) -> dict[str, int | float]:
        return {
            "evaluated_request_count": self.evaluated_request_count,
            "unlabeled_request_count": self.unlabeled_request_count,
            "unmatched_label_count": self.unmatched_label_count,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "accuracy": self.accuracy,
            "brier_score": self.brier_score,
            "threshold": self.threshold,
        }


def _automation_score(payload: Mapping[str, Any]) -> tuple[str, float]:
    request_id = payload.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        raise EvaluationError("detection request_id must be a non-empty string")
    score = payload.get("automation_score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise EvaluationError("detection automation_score must be a number")
    numeric_score = float(score)
    if not 0.0 <= numeric_score <= 1.0:
        raise EvaluationError("detection automation_score must be between 0 and 1")
    return request_id, numeric_score


def evaluate_automation_scores(
    detections: Iterable[Mapping[str, Any]],
    labels: Mapping[str, bool],
    *,
    threshold: float = 0.5,
) -> AutomationEvaluation:
    """Evaluate automation scores against authorized boolean labels in memory.

    Labels map a privacy-safe `request_id` to `True` for automated traffic and
    `False` for non-automated traffic. Unlabeled detections and unused labels
    are reported as coverage signals instead of being silently discarded.
    """

    if not 0.0 <= threshold <= 1.0:
        raise EvaluationError("threshold must be between 0 and 1")
    if any(not isinstance(request_id, str) or not request_id for request_id in labels):
        raise EvaluationError("label request_id must be a non-empty string")
    if any(not isinstance(value, bool) for value in labels.values()):
        raise EvaluationError("labels must map request IDs to boolean values")

    true_positive = false_positive = true_negative = false_negative = 0
    squared_error_total = 0.0
    evaluated = unlabeled = 0
    matched_labels: set[str] = set()
    seen_detection_ids: set[str] = set()

    for payload in detections:
        request_id, score = _automation_score(payload)
        if request_id in seen_detection_ids:
            raise EvaluationError(f"duplicate detection request_id: {request_id}")
        seen_detection_ids.add(request_id)
        label = labels.get(request_id)
        if label is None:
            unlabeled += 1
            continue

        matched_labels.add(request_id)
        evaluated += 1
        predicted = score >= threshold
        squared_error_total += (score - float(label)) ** 2
        if predicted and label:
            true_positive += 1
        elif predicted:
            false_positive += 1
        elif label:
            false_negative += 1
        else:
            true_negative += 1

    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    precision = true_positive / precision_denominator if precision_denominator else 0.0
    recall = true_positive / recall_denominator if recall_denominator else 0.0
    f1 = 2.0 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (true_positive + true_negative) / evaluated if evaluated else 0.0
    brier_score = squared_error_total / evaluated if evaluated else 0.0

    return AutomationEvaluation(
        evaluated_request_count=evaluated,
        unlabeled_request_count=unlabeled,
        unmatched_label_count=len(set(labels) - matched_labels),
        true_positive=true_positive,
        false_positive=false_positive,
        true_negative=true_negative,
        false_negative=false_negative,
        precision=precision,
        recall=recall,
        f1=f1,
        accuracy=accuracy,
        brier_score=brier_score,
        threshold=threshold,
    )
