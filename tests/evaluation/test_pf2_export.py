from __future__ import annotations

import json

import pytest

from agent_traffic_intelligence.evaluation.pf2.baseline import evaluate_pf2_baseline
from agent_traffic_intelligence.evaluation.pf2.export import (
    SCHEMAS,
    PF2ExportError,
    bigquery_ddl,
    build_bigquery_export,
)
from agent_traffic_intelligence.evaluation.pf2.protocol import (
    PF2_FEATURE_FAMILIES,
    PF2_TARGET_NAME,
    pf2_feature_names,
)

_FEATURES = pf2_feature_names()
_EXPORTED_AT = "2026-09-26T12:00:00+00:00"


def _session(index: int) -> str:
    return "hmac-sha256:" + f"{index:064x}"


def _model_row(automated: bool, **features: int | bool) -> dict[str, int | bool]:
    row: dict[str, int | bool] = dict.fromkeys(_FEATURES, 0)
    row["completion"] = False
    row.update(features)
    row[PF2_TARGET_NAME] = automated
    return row


def _corpus() -> tuple[list[dict[str, int | bool]], list[dict[str, int | str]]]:
    model_rows: list[dict[str, int | bool]] = []
    split_rows: list[dict[str, int | str]] = []
    for index in range(32):
        automated = index % 2 == 0
        model_rows.append(
            _model_row(
                automated,
                session_request_count=5 if automated else 8,
                delay_bin_under_1_count=4 if automated else 0,
                delay_bin_4_to_16_count=0 if automated else 4,
                route_start_count=1,
                completion=True,
            )
        )
        split_rows.append(
            {
                "row_index": index,
                "session_id": _session(index),
                "task": "task-detail" if index % 4 < 2 else "task-related",
                "collection_window": "w1" if index < 16 else "w2",
            }
        )
    return model_rows, split_rows


def _export(**overrides: object) -> dict[str, object]:
    model_rows, split_rows = _corpus()
    report = evaluate_pf2_baseline(model_rows, split_rows, resamples=32, seed=1).to_dict()
    options: dict[str, object] = {
        "run_id": "run-2026-09-26",
        "corpus_id": "controlled-pf2-2026-09",
        "exported_at": _EXPORTED_AT,
        "ati_version": "0.1.0.dev0",
    }
    options.update(overrides)
    return build_bigquery_export(model_rows, report, **options).to_dict()  # type: ignore[arg-type]


def test_export_produces_every_declared_table() -> None:
    export = _export()

    assert set(export["tables"]) == set(SCHEMAS)
    assert set(export["schemas"]) == set(SCHEMAS)
    assert len(export["tables"]["pf2_run_manifest"]) == 1


def test_export_rows_only_use_declared_schema_columns() -> None:
    export = _export()

    for table, rows in export["tables"].items():
        declared = {field["name"] for field in export["schemas"][table]}
        for row in rows:
            assert set(row) <= declared, table
            for field in export["schemas"][table]:
                if field["mode"] == "REQUIRED":
                    assert field["name"] in row, (table, field["name"])
                    assert row[field["name"]] is not None, (table, field["name"])


def test_export_never_contains_session_pseudonyms_or_audit_only_metadata() -> None:
    export = _export()

    serialized = json.dumps(export, sort_keys=True)
    assert "hmac-sha256:" not in serialized
    for prohibited in (
        "session_id",
        "request_id",
        "client_id",
        "row_index",
        "ua_provenance_bucket",
        "ati_campaign_id",
        "time_iso8601",
    ):
        for rows in export["tables"].values():
            for row in rows:
                assert prohibited not in row


def test_export_summarizes_features_by_class_without_per_session_rows() -> None:
    export = _export()

    summary = export["tables"]["pf2_feature_summary"]
    assert len(summary) == len(_FEATURES) * 2
    families = {row["feature_family"] for row in summary}
    assert families == set(PF2_FEATURE_FAMILIES)
    classes = {row["target_class"] for row in summary}
    assert classes == {"automated", "human_assisted"}
    for row in summary:
        assert row["session_count"] == 16
        assert row["minimum"] <= row["mean"] <= row["maximum"]
    # Aggregates only: no table may hold one row per session.
    for table, rows in export["tables"].items():
        if table != "pf2_feature_summary":
            continue
        assert len(rows) != 32


def test_export_carries_session_cluster_intervals_for_every_metric() -> None:
    export = _export()

    metrics = export["tables"]["pf2_baseline_metrics"]
    assert metrics
    for row in metrics:
        for metric in ("recall", "false_positive_rate", "pr_auc", "brier_score"):
            assert f"{metric}_ci_lower" in row
            assert f"{metric}_ci_upper" in row
            lower = row[f"{metric}_ci_lower"]
            upper = row[f"{metric}_ci_upper"]
            if lower is not None and upper is not None:
                assert lower <= upper


def test_export_records_one_ablation_row_per_family_and_split() -> None:
    export = _export()

    ablations = export["tables"]["pf2_baseline_ablations"]
    evaluated_splits = {
        row["split_name"]
        for row in export["tables"]["pf2_baseline_metrics"]
        if row["split_status"] == "evaluated"
    }
    assert len(ablations) == len(evaluated_splits) * len(PF2_FEATURE_FAMILIES)


def test_export_records_cohort_counts_by_class() -> None:
    export = _export()

    cohorts = export["tables"]["pf2_cohort_counts"]
    dimensions = {row["dimension"] for row in cohorts}
    assert dimensions == {"task", "collection_window"}
    assert all(row["session_count"] > 0 for row in cohorts)


@pytest.mark.parametrize("field", ["run_id", "corpus_id"])
def test_blank_identifiers_fail_closed(field: str) -> None:
    with pytest.raises(PF2ExportError, match=f"{field} must be a non-empty string"):
        _export(**{field: "  "})


def test_prohibited_model_column_fails_closed() -> None:
    model_rows, split_rows = _corpus()
    report = evaluate_pf2_baseline(model_rows, split_rows, resamples=8, seed=1).to_dict()
    model_rows[0]["ua_provenance_bucket"] = "scripted-http"  # type: ignore[assignment]

    with pytest.raises(PF2ExportError, match="prohibited column"):
        build_bigquery_export(
            model_rows,
            report,
            run_id="run",
            corpus_id="corpus",
            exported_at=_EXPORTED_AT,
            ati_version="0.1.0.dev0",
        )


def test_report_without_a_firewall_block_fails_closed() -> None:
    model_rows, split_rows = _corpus()
    report = evaluate_pf2_baseline(model_rows, split_rows, resamples=8, seed=1).to_dict()
    del report["firewall"]

    with pytest.raises(PF2ExportError, match="verdict and firewall block"):
        build_bigquery_export(
            model_rows,
            report,
            run_id="run",
            corpus_id="corpus",
            exported_at=_EXPORTED_AT,
            ati_version="0.1.0.dev0",
        )


def test_report_without_splits_fails_closed() -> None:
    model_rows, split_rows = _corpus()
    report = evaluate_pf2_baseline(model_rows, split_rows, resamples=8, seed=1).to_dict()
    report["splits"] = "not-a-list"

    with pytest.raises(PF2ExportError, match="splits list"):
        build_bigquery_export(
            model_rows,
            report,
            run_id="run",
            corpus_id="corpus",
            exported_at=_EXPORTED_AT,
            ati_version="0.1.0.dev0",
        )


def test_empty_model_table_fails_closed() -> None:
    with pytest.raises(PF2ExportError, match="automated target"):
        build_bigquery_export(
            [],
            {"splits": [], "verdict": {}, "firewall": {}},
            run_id="run",
            corpus_id="corpus",
            exported_at=_EXPORTED_AT,
            ati_version="0.1.0.dev0",
        )


def test_ddl_declares_every_table_and_required_column() -> None:
    ddl = bigquery_ddl("ati_pf2", project="example-project")

    for table, fields in SCHEMAS.items():
        assert f"`example-project.ati_pf2`.{table}" in ddl
        for field in fields:
            assert field["name"] in ddl
            if field["mode"] == "REQUIRED":
                assert f"{field['name']} {field['type']} NOT NULL" in ddl


def test_ddl_without_a_project_uses_the_bare_dataset() -> None:
    ddl = bigquery_ddl("ati_pf2")

    assert "`ati_pf2`.pf2_run_manifest" in ddl
    assert "example-project" not in ddl


@pytest.mark.parametrize(
    "dataset", ["", "bad-dataset", "with space", "semi;colon", "quote`tick"]
)
def test_invalid_dataset_name_fails_closed(dataset: str) -> None:
    with pytest.raises(PF2ExportError, match="alphanumeric BigQuery dataset"):
        bigquery_ddl(dataset)


@pytest.mark.parametrize("project", ["bad project", "semi;colon", "quote`tick"])
def test_invalid_project_name_fails_closed(project: str) -> None:
    with pytest.raises(PF2ExportError, match="valid BigQuery project"):
        bigquery_ddl("ati_pf2", project=project)


def test_single_class_corpus_export_omits_the_absent_class() -> None:
    model_rows = [
        _model_row(True, session_request_count=5 + index, route_start_count=1)
        for index in range(8)
    ]
    report = {
        "status": "blocked-single-class-split",
        "session_count": len(model_rows),
        "feature_count": len(_FEATURES),
        "feature_family_count": len(PF2_FEATURE_FAMILIES),
        "prevalence": 1.0,
        "l2": 1.0,
        "seed": 0,
        "resample_count": 8,
        "firewall": {
            "single_class_split_count": 1,
            "train_holdout_session_overlap_count": 0,
        },
        "cohorts": {"task": {"task-detail": {"automated": 8, "human_assisted": 0}}},
        "splits": [],
        "verdict": {
            "final_temporal_holdout": None,
            "logistic_beats_constant_on_final_temporal_holdout": None,
            "target_false_positive_rate": None,
            "meets_predeclared_false_positive_rate": None,
        },
    }

    export = build_bigquery_export(
        model_rows,
        report,
        run_id="single-class",
        corpus_id="controlled-pf2-2026-09",
        exported_at=_EXPORTED_AT,
        ati_version="0.1.0.dev0",
    ).to_dict()

    classes = {row["target_class"] for row in export["tables"]["pf2_feature_summary"]}
    assert classes == {"automated"}
    assert export["tables"]["pf2_baseline_metrics"] == []
    manifest = export["tables"]["pf2_run_manifest"][0]
    assert manifest["status"] == "blocked-single-class-split"
    assert manifest["prevalence"] == 1.0
