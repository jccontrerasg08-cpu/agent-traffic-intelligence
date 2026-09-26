from __future__ import annotations

import json
import random

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from agent_traffic_intelligence.evaluation.pf2.baseline import (
    PF2BaselineError,
    build_pf2_splits,
    evaluate_pf2_baseline,
)
from agent_traffic_intelligence.evaluation.pf2.protocol import (
    PF2_FEATURE_FAMILIES,
    PF2_TARGET_NAME,
    pf2_feature_names,
)

_FEATURES = pf2_feature_names()


def _session(index: int) -> str:
    return "hmac-sha256:" + f"{index:064x}"


def _model_row(automated: bool, **features: int | bool) -> dict[str, int | bool]:
    row: dict[str, int | bool] = dict.fromkeys(_FEATURES, 0)
    row["completion"] = False
    unknown = set(features) - set(_FEATURES)
    assert not unknown, unknown
    row.update(features)
    row[PF2_TARGET_NAME] = automated
    return row


def _corpus(
    *,
    sessions_per_cell: int = 8,
    tasks: tuple[str, ...] = ("task-detail", "task-related"),
    windows: tuple[str, ...] = ("w1", "w2"),
    separable: bool = True,
    seed: int = 3,
) -> tuple[list[dict[str, int | bool]], list[dict[str, int | str]]]:
    """Build a model table plus split manifest without touching the preflight."""

    generator = random.Random(seed)
    model_rows: list[dict[str, int | bool]] = []
    split_rows: list[dict[str, int | str]] = []
    index = 0
    for task in tasks:
        for window in windows:
            for automated in (True, False):
                for _ in range(sessions_per_cell):
                    if separable:
                        delay_fast = 4 if automated else 0
                        delay_slow = 0 if automated else 4
                    else:
                        delay_fast = generator.randint(0, 4)
                        delay_slow = generator.randint(0, 4)
                    model_rows.append(
                        _model_row(
                            automated,
                            session_request_count=5 + delay_fast,
                            delay_bin_under_1_count=delay_fast,
                            delay_bin_4_to_16_count=delay_slow,
                            route_start_count=1,
                            route_complete_count=1,
                            completion=True,
                            status_2xx_count=5,
                        )
                    )
                    split_rows.append(
                        {
                            "row_index": index,
                            "session_id": _session(index),
                            "task": task,
                            "collection_window": window,
                        }
                    )
                    index += 1
    return model_rows, split_rows


def _report(**kwargs: object) -> dict[str, object]:
    model_rows, split_rows = _corpus(**kwargs)  # type: ignore[arg-type]
    return evaluate_pf2_baseline(model_rows, split_rows, resamples=64, seed=5).to_dict()


def test_baseline_ladder_evaluates_every_declared_holdout() -> None:
    report = _report()

    assert report["status"] == "evaluated"
    assert report["session_count"] == 64
    assert report["feature_count"] == len(_FEATURES)
    assert report["prevalence"] == 0.5
    splits = report["splits"]
    assert isinstance(splits, list)
    kinds = {entry["kind"] for entry in splits}
    assert kinds == {"temporal", "unseen_task", "grouped_session"}
    assert sum(entry["final_temporal_holdout"] for entry in splits) == 1
    for entry in splits:
        assert entry["status"] == "evaluated"
        assert set(entry["models"]) == {"constant_prevalence", "l2_logistic_regression"}
        assert set(entry["ablations"]) == set(PF2_FEATURE_FAMILIES)


def test_regularized_logistic_beats_constant_baseline_on_separable_corpus() -> None:
    report = _report(separable=True)

    verdict = report["verdict"]
    assert verdict["final_temporal_holdout"] == "temporal:w2"
    assert verdict["logistic_beats_constant_on_final_temporal_holdout"] is True
    final = next(entry for entry in report["splits"] if entry["final_temporal_holdout"])
    logistic = final["models"]["l2_logistic_regression"]
    constant = final["models"]["constant_prevalence"]
    assert logistic["pr_auc"] > constant["pr_auc"]
    assert logistic["brier_score"] < constant["brier_score"]
    assert logistic["converged"] is True


def test_logistic_does_not_beat_constant_baseline_on_uninformative_corpus() -> None:
    report = _report(separable=False, sessions_per_cell=12, seed=17)

    verdict = report["verdict"]
    assert verdict["logistic_beats_constant_on_final_temporal_holdout"] is False


def test_temporal_holdout_never_trains_on_a_later_collection_window() -> None:
    windows = {0: "w1", 1: "w2", 2: "w3"}
    tasks = {0: "t", 1: "t", 2: "t"}

    splits = build_pf2_splits(tasks, windows)

    temporal = [split for split in splits if split.kind == "temporal"]
    assert [split.name for split in temporal] == ["temporal:w2", "temporal:w3"]
    assert temporal[0].train_rows == (0,)
    assert temporal[0].holdout_rows == (1,)
    assert temporal[1].train_rows == (0, 1)
    assert temporal[1].holdout_rows == (2,)
    assert temporal[-1].final_temporal_holdout is True
    assert temporal[0].final_temporal_holdout is False


def test_unseen_task_and_grouped_session_holdouts_stay_disjoint() -> None:
    tasks = {index: f"task-{index % 3}" for index in range(12)}
    windows: dict[int, str | None] = dict.fromkeys(range(12), "w1")

    splits = build_pf2_splits(tasks, windows, grouped_holdout_fraction=0.25, seed=1)

    task_splits = [split for split in splits if split.kind == "unseen_task"]
    assert len(task_splits) == 3
    for split in splits:
        assert not set(split.train_rows) & set(split.holdout_rows)
        assert split.holdout_rows
    grouped = next(split for split in splits if split.kind == "grouped_session")
    assert len(grouped.holdout_rows) == 3
    assert len(grouped.train_rows) == 9


def test_report_is_deterministic_for_one_seed() -> None:
    model_rows, split_rows = _corpus()

    first = evaluate_pf2_baseline(model_rows, split_rows, resamples=64, seed=9).to_dict()
    second = evaluate_pf2_baseline(model_rows, split_rows, resamples=64, seed=9).to_dict()

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_report_never_emits_opaque_session_pseudonyms_or_audit_only_columns() -> None:
    model_rows, split_rows = _corpus()

    report = evaluate_pf2_baseline(model_rows, split_rows, resamples=16, seed=2).to_dict()

    serialized = json.dumps(report, sort_keys=True)
    for row in split_rows:
        assert str(row["session_id"]) not in serialized
    assert "hmac-sha256:" not in serialized
    assert report["firewall"]["split_metadata_reached_estimator"] is False
    assert report["firewall"]["train_holdout_session_overlap_count"] == 0
    assert report["firewall"]["duplicate_session_count"] == 0


def test_operating_threshold_comes_from_the_training_partition_only() -> None:
    model_rows, split_rows = _corpus()
    baseline = evaluate_pf2_baseline(
        model_rows, split_rows, resamples=16, seed=4, target_false_positive_rate=0.1
    ).to_dict()

    final_rows = {
        row["row_index"] for row in split_rows if row["collection_window"] == "w2"
    }
    mutated = [
        _model_row(bool(row[PF2_TARGET_NAME]), session_request_count=99)
        if index in final_rows
        else row
        for index, row in enumerate(model_rows)
    ]
    changed = evaluate_pf2_baseline(
        mutated, split_rows, resamples=16, seed=4, target_false_positive_rate=0.1
    ).to_dict()

    def threshold(report: dict[str, object]) -> float:
        final = next(entry for entry in report["splits"] if entry["final_temporal_holdout"])
        value = final["models"]["l2_logistic_regression"]["threshold"]
        assert isinstance(value, float)
        return value

    assert threshold(baseline) == threshold(changed)


def test_predeclared_false_positive_rate_is_reported_without_holdout_tuning() -> None:
    model_rows, split_rows = _corpus()

    report = evaluate_pf2_baseline(
        model_rows, split_rows, resamples=32, seed=6, target_false_positive_rate=0.25
    ).to_dict()

    verdict = report["verdict"]
    assert verdict["target_false_positive_rate"] == 0.25
    assert isinstance(verdict["meets_predeclared_false_positive_rate"], bool)
    final = next(entry for entry in report["splits"] if entry["final_temporal_holdout"])
    for model in final["models"].values():
        assert model["threshold_source"] == "train-partition-target-fpr"


def test_fixed_threshold_is_used_without_a_predeclared_operating_point() -> None:
    report = _report()

    final = next(entry for entry in report["splits"] if entry["final_temporal_holdout"])
    for model in final["models"].values():
        assert model["threshold"] == 0.5
        assert model["threshold_source"] == "fixed-0.5"


def test_ablation_removes_each_permitted_feature_family() -> None:
    model_rows, split_rows = _corpus()

    report = evaluate_pf2_baseline(model_rows, split_rows, resamples=16, seed=8).to_dict()

    final = next(entry for entry in report["splits"] if entry["final_temporal_holdout"])
    ablations = final["ablations"]
    assert set(ablations) == set(PF2_FEATURE_FAMILIES)
    for family, result in ablations.items():
        assert result["status"] == "evaluated"
        assert result["removed_feature_count"] == len(PF2_FEATURE_FAMILIES[family])


def test_ablation_detects_the_only_informative_feature_family() -> None:
    model_rows: list[dict[str, int | bool]] = []
    split_rows: list[dict[str, int | str]] = []
    for index in range(48):
        automated = index % 2 == 0
        model_rows.append(
            _model_row(
                automated,
                delay_bin_under_1_count=5 if automated else 0,
                delay_bin_4_to_16_count=0 if automated else 5,
            )
        )
        split_rows.append(
            {
                "row_index": index,
                "session_id": _session(index),
                "task": f"task-{index % 2}",
                "collection_window": "w1" if index < 24 else "w2",
            }
        )

    report = evaluate_pf2_baseline(model_rows, split_rows, resamples=16, seed=0).to_dict()

    final = next(entry for entry in report["splits"] if entry["final_temporal_holdout"])
    full_pr_auc = final["models"]["l2_logistic_regression"]["pr_auc"]
    tempo = final["ablations"]["coarsened_tempo"]
    navigation = final["ablations"]["session_navigation"]
    assert full_pr_auc == 1.0
    assert tempo["pr_auc"] < full_pr_auc
    assert tempo["pr_auc_delta"] < 0
    assert navigation["pr_auc"] == full_pr_auc


def test_single_class_split_fails_closed_without_metrics() -> None:
    model_rows: list[dict[str, int | bool]] = []
    split_rows: list[dict[str, int | str]] = []
    for index in range(16):
        # Every session in the later window is automated, so no class contrast exists.
        window = "w1" if index < 8 else "w2"
        automated = True if window == "w2" else index % 2 == 0
        model_rows.append(_model_row(automated, session_request_count=5 + index))
        split_rows.append(
            {
                "row_index": index,
                "session_id": _session(index),
                "task": "task-a",
                "collection_window": window,
            }
        )

    report = evaluate_pf2_baseline(model_rows, split_rows, resamples=16, seed=0).to_dict()

    assert report["status"] == "blocked-single-class-split"
    assert report["firewall"]["single_class_split_count"] >= 1
    blocked = next(entry for entry in report["splits"] if entry["status"] == "blocked-single-class")
    assert blocked["models"] == {}
    assert blocked["ablations"] == {}
    assert blocked["logistic_beats_constant"] is None
    assert report["verdict"]["logistic_beats_constant_on_final_temporal_holdout"] is None


def test_corpus_without_a_collection_window_reports_no_temporal_holdout() -> None:
    model_rows, split_rows = _corpus(windows=("w1",))
    for row in split_rows:
        del row["collection_window"]

    report = evaluate_pf2_baseline(model_rows, split_rows, resamples=16, seed=0).to_dict()

    assert report["status"] == "blocked-no-temporal-holdout"
    assert report["verdict"]["final_temporal_holdout"] is None
    assert report["cohorts"]["collection_window"] == {}


def test_session_cluster_intervals_bracket_each_reported_metric() -> None:
    report = _report()

    final = next(entry for entry in report["splits"] if entry["final_temporal_holdout"])
    intervals = final["models"]["l2_logistic_regression"]["session_cluster_intervals"]
    assert set(intervals) == {"recall", "false_positive_rate", "pr_auc", "brier_score"}
    for interval in intervals.values():
        if interval is None:
            continue
        assert interval["lower"] <= interval["upper"]
        assert interval["resample_count"] >= 2


def test_feature_inventory_reports_cardinality_and_missingness() -> None:
    report = _report()

    inventory = report["feature_inventory"]
    assert set(inventory) == set(_FEATURES)
    for entry in inventory.values():
        assert entry["missing_value_count"] == 0
        assert entry["distinct_value_count"] >= 1
    assert inventory["delay_bin_under_1_count"]["distinct_value_count"] > 1


def test_cohort_counts_cover_every_task_and_window_by_class() -> None:
    report = _report()

    cohorts = report["cohorts"]
    assert set(cohorts["task"]) == {"task-detail", "task-related"}
    assert set(cohorts["collection_window"]) == {"w1", "w2"}
    for bucket in cohorts["task"].values():
        assert bucket == {"automated": 16, "human_assisted": 16}


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"ati_campaign_id": "owned-2026"}, "prohibited column"),
        ({"session_id": "hmac-sha256:" + "a" * 64}, "prohibited column"),
        ({"ua_provenance_bucket": "scripted-http"}, "prohibited column"),
        ({"time_iso8601": "2026-09-26T00:00:00+00:00"}, "prohibited column"),
        ({"request_id": "abc"}, "prohibited column"),
    ],
)
def test_prohibited_model_column_fails_closed(mutation: dict[str, str], message: str) -> None:
    model_rows, split_rows = _corpus(sessions_per_cell=2)
    model_rows[0].update(mutation)  # type: ignore[arg-type]

    with pytest.raises(PF2BaselineError, match=message):
        evaluate_pf2_baseline(model_rows, split_rows, resamples=4, seed=0)


def test_missing_target_fails_closed() -> None:
    model_rows, split_rows = _corpus(sessions_per_cell=2)
    del model_rows[0][PF2_TARGET_NAME]

    with pytest.raises(PF2BaselineError, match="missing the automated target"):
        evaluate_pf2_baseline(model_rows, split_rows, resamples=4, seed=0)


def test_non_boolean_target_fails_closed() -> None:
    model_rows, split_rows = _corpus(sessions_per_cell=2)
    model_rows[0][PF2_TARGET_NAME] = 1

    with pytest.raises(PF2BaselineError, match="target must be a boolean"):
        evaluate_pf2_baseline(model_rows, split_rows, resamples=4, seed=0)


def test_missing_feature_fails_closed() -> None:
    model_rows, split_rows = _corpus(sessions_per_cell=2)
    del model_rows[0]["route_start_count"]

    with pytest.raises(PF2BaselineError, match="missing feature"):
        evaluate_pf2_baseline(model_rows, split_rows, resamples=4, seed=0)


def test_non_integer_feature_fails_closed() -> None:
    model_rows, split_rows = _corpus(sessions_per_cell=2)
    model_rows[0]["session_request_count"] = 1.5  # type: ignore[assignment]

    with pytest.raises(PF2BaselineError, match="must be an integer or boolean"):
        evaluate_pf2_baseline(model_rows, split_rows, resamples=4, seed=0)


def test_empty_model_table_fails_closed() -> None:
    with pytest.raises(PF2BaselineError, match="at least one session row"):
        evaluate_pf2_baseline([], [], resamples=4, seed=0)


def test_single_class_model_table_fails_closed() -> None:
    model_rows = [_model_row(True, session_request_count=index) for index in range(4)]
    split_rows: list[dict[str, int | str]] = [
        {
            "row_index": index,
            "session_id": _session(index),
            "task": "task-a",
            "collection_window": "w1",
        }
        for index in range(4)
    ]

    with pytest.raises(PF2BaselineError, match="must contain both classes"):
        evaluate_pf2_baseline(model_rows, split_rows, resamples=4, seed=0)


def test_split_manifest_row_count_mismatch_fails_closed() -> None:
    model_rows, split_rows = _corpus(sessions_per_cell=2)

    with pytest.raises(PF2BaselineError, match="every model table row exactly once"):
        evaluate_pf2_baseline(model_rows, split_rows[:-1], resamples=4, seed=0)


def test_duplicate_split_row_index_fails_closed() -> None:
    model_rows, split_rows = _corpus(sessions_per_cell=2)
    split_rows[1]["row_index"] = split_rows[0]["row_index"]

    with pytest.raises(PF2BaselineError, match="duplicate row_index"):
        evaluate_pf2_baseline(model_rows, split_rows, resamples=4, seed=0)


def test_duplicate_session_pseudonym_fails_closed() -> None:
    model_rows, split_rows = _corpus(sessions_per_cell=2)
    split_rows[1]["session_id"] = split_rows[0]["session_id"]

    with pytest.raises(PF2BaselineError, match="duplicate session pseudonym"):
        evaluate_pf2_baseline(model_rows, split_rows, resamples=4, seed=0)


def test_transparent_session_identifier_fails_closed() -> None:
    model_rows, split_rows = _corpus(sessions_per_cell=2)
    split_rows[0]["session_id"] = "192.0.2.10"

    with pytest.raises(PF2BaselineError, match="opaque HMAC pseudonym"):
        evaluate_pf2_baseline(model_rows, split_rows, resamples=4, seed=0)


def test_unsupported_split_field_fails_closed() -> None:
    model_rows, split_rows = _corpus(sessions_per_cell=2)
    split_rows[0]["family"] = "playwright"

    with pytest.raises(PF2BaselineError, match="unsupported field"):
        evaluate_pf2_baseline(model_rows, split_rows, resamples=4, seed=0)


def test_out_of_range_split_row_index_fails_closed() -> None:
    model_rows, split_rows = _corpus(sessions_per_cell=2)
    split_rows[0]["row_index"] = len(model_rows)

    with pytest.raises(PF2BaselineError, match="outside the model table"):
        evaluate_pf2_baseline(model_rows, split_rows, resamples=4, seed=0)


def test_blank_task_label_fails_closed() -> None:
    model_rows, split_rows = _corpus(sessions_per_cell=2)
    split_rows[0]["task"] = "   "

    with pytest.raises(PF2BaselineError, match="non-empty audit label"):
        evaluate_pf2_baseline(model_rows, split_rows, resamples=4, seed=0)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"l2": 0.0}, "l2 must be positive"),
        ({"l2": -1.0}, "l2 must be positive"),
        ({"resamples": 1}, "resamples must be at least 2"),
        ({"target_false_positive_rate": 1.5}, "between 0 and 1"),
        ({"target_false_positive_rate": -0.1}, "between 0 and 1"),
        ({"grouped_holdout_fraction": 0.0}, "between 0 and 1"),
        ({"grouped_holdout_fraction": 1.0}, "between 0 and 1"),
    ],
)
def test_invalid_baseline_options_fail_closed(kwargs: dict[str, float], message: str) -> None:
    model_rows, split_rows = _corpus(sessions_per_cell=2)
    options: dict[str, object] = {"resamples": 4, "seed": 0}
    options.update(kwargs)

    with pytest.raises(PF2BaselineError, match=message):
        evaluate_pf2_baseline(model_rows, split_rows, **options)  # type: ignore[arg-type]


def test_preflight_output_feeds_the_baseline_directly() -> None:
    from datetime import UTC, datetime, timedelta

    from agent_traffic_intelligence.evaluation.pf2.protocol import prepare_pf2_dataset

    records = []
    labels: dict[str, bool] = {}
    tasks: dict[str, str] = {}
    windows: dict[str, str] = {}
    base = datetime(2026, 9, 26, tzinfo=UTC)
    for index in range(32):
        automated = index % 2 == 0
        session = _session(index)
        labels[session] = automated
        tasks[session] = "task-detail" if index % 4 < 2 else "task-related"
        windows[session] = "w1" if index < 16 else "w2"
        moment = base + timedelta(hours=0 if index < 16 else 8)
        for path in ("/lab/start", "/lab/page/landing", "/lab/page/catalog", "/lab/complete"):
            moment = moment + timedelta(seconds=0.2 if automated else 6.0)
            records.append(
                {
                    "session_id": session,
                    "request_uri": path,
                    "request_method": "GET",
                    "status": 200,
                    "time_iso8601": moment.isoformat(),
                }
            )

    dataset = prepare_pf2_dataset(
        records,
        labels_by_session=labels,
        task_by_session=tasks,
        collection_window_by_session=windows,
        min_sessions_per_task_class=4,
    )
    assert dataset.preflight["status"] == "ready-for-baseline"

    report = evaluate_pf2_baseline(
        dataset.model_rows, dataset.split_rows, resamples=32, seed=1
    ).to_dict()

    assert report["status"] == "evaluated"
    assert report["session_count"] == 32
    assert report["verdict"]["logistic_beats_constant_on_final_temporal_holdout"] is True


@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    sessions_per_cell=st.integers(min_value=2, max_value=5),
    seed=st.integers(min_value=0, max_value=2**16),
    separable=st.booleans(),
)
def test_arbitrary_valid_corpora_keep_splits_disjoint_and_leak_nothing(
    sessions_per_cell: int, seed: int, separable: bool
) -> None:
    model_rows, split_rows = _corpus(
        sessions_per_cell=sessions_per_cell, separable=separable, seed=seed
    )

    report = evaluate_pf2_baseline(model_rows, split_rows, resamples=8, seed=seed).to_dict()

    assert report["firewall"]["train_holdout_session_overlap_count"] == 0
    assert "hmac-sha256:" not in json.dumps(report, sort_keys=True)
    for entry in report["splits"]:
        assert entry["train_session_count"] + entry["holdout_session_count"] <= len(model_rows)
        for model in entry["models"].values():
            assert 0.0 <= model["brier_score"] <= 1.0
            assert 0.0 <= model["recall"] <= 1.0
            if model["pr_auc"] is not None:
                assert 0.0 <= model["pr_auc"] <= 1.0
