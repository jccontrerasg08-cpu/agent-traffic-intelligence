import pytest

from agent_traffic_intelligence.evaluation import EvaluationError, evaluate_automation_scores


def detection(request_id: str, score: float) -> dict[str, object]:
    return {
        "schema_version": 1,
        "request_id": request_id,
        "automation_score": score,
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
        "threshold": 0.5,
    }


@pytest.mark.parametrize("threshold", (-0.1, 1.1))
def test_evaluation_rejects_invalid_threshold(threshold: float) -> None:
    with pytest.raises(EvaluationError, match="threshold"):
        evaluate_automation_scores([], {}, threshold=threshold)


def test_evaluation_rejects_malformed_detection_payload() -> None:
    with pytest.raises(EvaluationError, match="automation_score"):
        evaluate_automation_scores([{"request_id": "a", "automation_score": True}], {"a": True})
