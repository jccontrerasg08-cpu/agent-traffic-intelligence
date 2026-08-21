"""Local, privacy-minimized evaluation helpers for labeled detection outputs."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any


class EvaluationError(ValueError):
    """Raised when an evaluation corpus does not meet ATI's minimal contract."""


_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "corpus_id",
        "authorized",
        "collection_start",
        "collection_end",
        "split_strategies",
        "known_sampling_biases",
    }
)
_REQUIRED_SPLIT_STRATEGIES = frozenset(
    {
        "grouped_session_client",
        "temporal_holdout",
        "unseen_family_holdout",
        "provider_ua_ablation",
    }
)
_CALIBRATION_BIN_COUNT = 10


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
    false_positive_rate: float | None
    false_negative_rate: float | None
    pr_auc: float | None
    expected_calibration_error: float | None
    threshold: float

    def to_dict(self) -> dict[str, int | float | None]:
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
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "pr_auc": self.pr_auc,
            "expected_calibration_error": self.expected_calibration_error,
            "threshold": self.threshold,
        }


def _pr_auc(scored_labels: list[tuple[float, bool]]) -> float | None:
    """Calculate threshold-based average precision, or None without positives."""

    positive_count = sum(label for _, label in scored_labels)
    if not positive_count:
        return None

    ranked = sorted(scored_labels, key=lambda item: item[0], reverse=True)
    true_positive = false_positive = 0
    previous_recall = 0.0
    area = 0.0
    index = 0
    while index < len(ranked):
        score = ranked[index][0]
        group_end = index
        while group_end < len(ranked) and ranked[group_end][0] == score:
            group_end += 1
        true_positive += sum(label for _, label in ranked[index:group_end])
        false_positive += group_end - index - sum(
            label for _, label in ranked[index:group_end]
        )
        recall = true_positive / positive_count
        precision = true_positive / (true_positive + false_positive)
        area += (recall - previous_recall) * precision
        previous_recall = recall
        index = group_end
    return area


def _expected_calibration_error(scored_labels: list[tuple[float, bool]]) -> float | None:
    """Calculate ECE with ten fixed-width confidence bins."""

    if not scored_labels:
        return None
    bin_count = [0] * _CALIBRATION_BIN_COUNT
    bin_score_total = [0.0] * _CALIBRATION_BIN_COUNT
    bin_positive_total = [0] * _CALIBRATION_BIN_COUNT
    for score, label in scored_labels:
        bucket = min(int(score * _CALIBRATION_BIN_COUNT), _CALIBRATION_BIN_COUNT - 1)
        bin_count[bucket] += 1
        bin_score_total[bucket] += score
        bin_positive_total[bucket] += label

    sample_count = len(scored_labels)
    return sum(
        (count / sample_count)
        * abs((bin_score_total[index] / count) - (bin_positive_total[index] / count))
        for index, count in enumerate(bin_count)
        if count
    )


def validate_corpus_manifest(manifest: Mapping[str, Any]) -> str:
    """Reject unapproved or leakage-prone evaluation corpus metadata."""

    unexpected_fields = set(manifest) - _MANIFEST_FIELDS
    missing_fields = _MANIFEST_FIELDS - set(manifest)
    if unexpected_fields:
        raise EvaluationError("corpus manifest contains unsupported fields")
    if missing_fields:
        raise EvaluationError("corpus manifest is missing required fields")
    if (
        isinstance(manifest["schema_version"], bool)
        or manifest["schema_version"] != 1
    ):
        raise EvaluationError("corpus manifest schema_version must be 1")
    corpus_id = manifest["corpus_id"]
    if not isinstance(corpus_id, str) or not corpus_id.strip():
        raise EvaluationError("corpus manifest corpus_id must be a non-empty string")
    if manifest["authorized"] is not True:
        raise EvaluationError("corpus manifest must explicitly be authorized")

    collection_times: list[datetime] = []
    for field in ("collection_start", "collection_end"):
        value = manifest[field]
        if not isinstance(value, str) or not value:
            raise EvaluationError(f"corpus manifest {field} must be an ISO 8601 timestamp")
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise EvaluationError(
                f"corpus manifest {field} must be an ISO 8601 timestamp"
            ) from exc
        if parsed.tzinfo is None:
            raise EvaluationError(f"corpus manifest {field} must include a timezone")
        collection_times.append(parsed)
    if collection_times[1] <= collection_times[0]:
        raise EvaluationError("corpus manifest collection_end must be after collection_start")

    split_strategies = manifest["split_strategies"]
    if not isinstance(split_strategies, list) or any(
        not isinstance(item, str) for item in split_strategies
    ):
        raise EvaluationError("corpus manifest split_strategies must be a list of strings")
    if (
        len(split_strategies) != len(set(split_strategies))
        or set(split_strategies) != _REQUIRED_SPLIT_STRATEGIES
    ):
        raise EvaluationError(
            "corpus manifest split_strategies must contain each required split once"
        )

    sampling_biases = manifest["known_sampling_biases"]
    if not isinstance(sampling_biases, list) or not sampling_biases or any(
        not isinstance(item, str) or not item.strip() for item in sampling_biases
    ):
        raise EvaluationError(
            "corpus manifest known_sampling_biases must be a non-empty list of strings"
        )
    return corpus_id


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
    scored_labels: list[tuple[float, bool]] = []
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
        scored_labels.append((score, label))
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
    negative_count = true_negative + false_positive
    positive_count = true_positive + false_negative

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
        false_positive_rate=(
            false_positive / negative_count if negative_count else None
        ),
        false_negative_rate=(
            false_negative / positive_count if positive_count else None
        ),
        pr_auc=_pr_auc(scored_labels),
        expected_calibration_error=_expected_calibration_error(scored_labels),
        threshold=threshold,
    )


_SESSION_ID = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")


def _stratified_metadata(
    request_id: str, metadata: Mapping[str, Any]
) -> tuple[str | None, str, str, str, str]:
    session_id = metadata.get("session_id")
    if session_id is not None and (
        not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id)
    ):
        raise EvaluationError(f"metadata session_id is invalid for request_id: {request_id}")
    values: list[str] = []
    for field in ("family", "provider", "ua_bucket", "time_iso8601"):
        value = metadata.get(field)
        if not isinstance(value, str) or not value.strip():
            raise EvaluationError(
                f"metadata {field} must be non-empty for request_id: {request_id}"
            )
        values.append(value)
    try:
        observed_at = datetime.fromisoformat(values[3])
    except ValueError as exc:
        raise EvaluationError(
            f"metadata time_iso8601 must be ISO 8601 for request_id: {request_id}"
        ) from exc
    if observed_at.tzinfo is None:
        raise EvaluationError(
            f"metadata time_iso8601 must include a timezone for request_id: {request_id}"
        )
    return session_id, values[0], values[1], values[2], observed_at.date().isoformat()


def _stratified_metrics(
    detections: list[Mapping[str, Any]], labels: Mapping[str, bool], threshold: float
) -> dict[str, int | float | None]:
    return evaluate_automation_scores(detections, labels, threshold=threshold).to_dict()


def evaluate_stratified_automation_scores(
    detections: Iterable[Mapping[str, Any]],
    labels: Mapping[str, bool],
    metadata_by_request_id: Mapping[str, Mapping[str, Any]],
    *,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Evaluate labeled detections by temporal, family and provider/UA holdout strata.

    Metadata is supplied locally and may contain only an opaque session pseudonym plus
    declared family, provider and coarse User-Agent bucket. The result reports group
    counts and metrics, never raw sessions, request identifiers or User-Agent strings.
    """

    materialized = list(detections)
    overall = _stratified_metrics(materialized, labels, threshold)
    by_family: dict[str, list[Mapping[str, Any]]] = {}
    by_day: dict[str, list[Mapping[str, Any]]] = {}
    by_provider_ua: dict[str, list[Mapping[str, Any]]] = {}
    selected_labels: dict[str, bool] = {}
    sessions: set[str] = set()
    missing_metadata = sessionless = 0

    for detection in materialized:
        request_id, _ = _automation_score(detection)
        if request_id not in labels:
            continue
        metadata = metadata_by_request_id.get(request_id)
        if metadata is None:
            missing_metadata += 1
            continue
        session_id, family, provider, ua_bucket, day = _stratified_metadata(request_id, metadata)
        if session_id is None:
            sessionless += 1
            continue
        sessions.add(session_id)
        selected_labels[request_id] = labels[request_id]
        by_family.setdefault(family, []).append(detection)
        by_day.setdefault(day, []).append(detection)
        by_provider_ua.setdefault(f"provider={provider}|ua={ua_bucket}", []).append(detection)

    def summarize(
        groups: Mapping[str, list[Mapping[str, Any]]]
    ) -> dict[str, dict[str, int | float | None]]:
        return {
            name: _stratified_metrics(
                group,
                {
                    request_id: selected_labels[request_id]
                    for request_id, _ in map(_automation_score, group)
                },
                threshold,
            )
            for name, group in sorted(groups.items())
        }

    return {
        "overall": overall,
        "integrity": {
            "missing_metadata_count": missing_metadata,
            "session_group_count": len(sessions),
            "sessionless_request_count": sessionless,
        },
        "splits": {
            "grouped_session_client": {
                "session_group_count": len(sessions),
                "sessionless_request_count": sessionless,
            },
            "temporal_holdout": summarize(by_day),
            "unseen_family_holdout": summarize(by_family),
            "provider_ua_ablation": summarize(by_provider_ua),
        },
    }
