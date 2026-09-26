import pytest

from agent_traffic_intelligence.evaluation import (
    EvaluationError,
    evaluate_automation_scores,
    validate_corpus_manifest,
)


def detection(request_id: str, score: float) -> dict[str, object]:
    return {
        "schema_version": 1,
        "request_id": request_id,
        "automation_score": score,
    }


def manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "corpus_id": "owned-shadow-2026-08",
        "authorized": True,
        "collection_start": "2026-08-01T00:00:00Z",
        "collection_end": "2026-08-02T00:00:00Z",
        "split_strategies": [
            "grouped_session_client",
            "temporal_holdout",
            "unseen_family_holdout",
            "provider_ua_ablation",
        ],
        "known_sampling_biases": ["controlled-traffic-overrepresentation"],
    }


def test_evaluation_reports_confusion_metrics_coverage_and_brier_score() -> None:
    result = evaluate_automation_scores(
        [
            detection("a", 0.9),
            detection("b", 0.7),
            detection("c", 0.2),
            detection("unlabeled", 0.1),
        ],
        {"a": True, "b": False, "c": False, "missing": True},
        threshold=0.5,
    )

    assert result.to_dict() == {
        "evaluated_request_count": 3,
        "unlabeled_request_count": 1,
        "unmatched_label_count": 1,
        "true_positive": 1,
        "false_positive": 1,
        "true_negative": 1,
        "false_negative": 0,
        "precision": 0.5,
        "recall": 1.0,
        "f1": pytest.approx(2 / 3),
        "accuracy": pytest.approx(2 / 3),
        "brier_score": pytest.approx((0.01 + 0.49 + 0.04) / 3),
        "false_positive_rate": pytest.approx(0.5),
        "false_negative_rate": pytest.approx(0.0),
        "pr_auc": pytest.approx(1.0),
        "expected_calibration_error": pytest.approx(1 / 3),
        "threshold": 0.5,
    }


def test_evaluation_returns_none_for_metrics_without_a_class() -> None:
    result = evaluate_automation_scores(
        [detection("a", 0.1), detection("b", 0.2)],
        {"a": False, "b": False},
    )

    assert result.false_positive_rate == 0.0
    assert result.false_negative_rate is None
    assert result.pr_auc is None
    assert result.expected_calibration_error == pytest.approx(0.15)


@pytest.mark.parametrize("threshold", (-0.1, 1.1))
def test_evaluation_rejects_invalid_threshold(threshold: float) -> None:
    with pytest.raises(EvaluationError, match="threshold"):
        evaluate_automation_scores([], {}, threshold=threshold)


def test_evaluation_rejects_malformed_detection_payload() -> None:
    with pytest.raises(EvaluationError, match="automation_score"):
        evaluate_automation_scores([{"request_id": "a", "automation_score": True}], {"a": True})


def test_evaluation_rejects_label_with_empty_request_id() -> None:
    with pytest.raises(EvaluationError, match="label request_id"):
        evaluate_automation_scores([], {"": True})


def test_corpus_manifest_requires_authorization_leakage_splits_and_biases() -> None:
    assert validate_corpus_manifest(manifest()) == "owned-shadow-2026-08"

    missing_split = manifest()
    missing_split["split_strategies"] = ["grouped_session_client"]
    with pytest.raises(EvaluationError, match="split_strategies"):
        validate_corpus_manifest(missing_split)

    unauthorized = manifest()
    unauthorized["authorized"] = False
    with pytest.raises(EvaluationError, match="authorized"):
        validate_corpus_manifest(unauthorized)

    invalid_version = manifest()
    invalid_version["schema_version"] = True
    with pytest.raises(EvaluationError, match="schema_version"):
        validate_corpus_manifest(invalid_version)


def test_corpus_manifest_rejects_unknown_fields_and_invalid_collection_window() -> None:
    unknown = manifest()
    unknown["raw_ip_address"] = "203.0.113.9"
    with pytest.raises(EvaluationError, match="unsupported fields"):
        validate_corpus_manifest(unknown)

    invalid_window = manifest()
    invalid_window["collection_end"] = "2026-08-01T00:00:00Z"
    with pytest.raises(EvaluationError, match="collection_end"):
        validate_corpus_manifest(invalid_window)
