"""Prepare privacy-safe warehouse artifacts from an ATI-PF-2 baseline run.

ATI never uploads a corpus. This module only writes local, aggregate, firewall-checked
tables plus the schema and DDL an operator needs to load them deliberately. The ATI-PF-2
split manifest is never exportable: it carries opaque session pseudonyms and audit-only
task labels, so it stays local by construction and this module refuses to accept it.

Per-session feature rows are not exported either. A rare feature vector can single out a
session, which the controlled-corpus feature contract treats as a high-resolution
indirect identifier, so the feature table is reduced to per-class aggregates.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agent_traffic_intelligence.evaluation.pf2.baseline import (
    PF2BaselineError,
    assert_pf2_model_table,
)
from agent_traffic_intelligence.evaluation.pf2.protocol import PF2_FEATURE_FAMILIES, PF2_TARGET_NAME

_PROHIBITED_EXPORT_KEYS = frozenset(
    {
        "session_id",
        "request_id",
        "client_id",
        "row_index",
        "task",
        "collection_window",
        "ati_campaign_id",
        "ua_provenance_bucket",
        "time_iso8601",
        "remote_addr",
    }
)
_INTERVAL_METRICS = ("recall", "false_positive_rate", "pr_auc", "brier_score")


class PF2ExportError(ValueError):
    """Raised when a warehouse export would leak audit-only or identifying material."""


@dataclass(frozen=True, slots=True)
class PF2Export:
    """Newline-delimited table rows plus their BigQuery schemas and load DDL."""

    tables: dict[str, tuple[dict[str, Any], ...]]
    schemas: dict[str, tuple[dict[str, str], ...]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tables": {name: list(rows) for name, rows in self.tables.items()},
            "schemas": {name: list(fields) for name, fields in self.schemas.items()},
        }


def _field(name: str, field_type: str, mode: str = "NULLABLE") -> dict[str, str]:
    return {"name": name, "type": field_type, "mode": mode}


_RUN_MANIFEST_SCHEMA = (
    _field("run_id", "STRING", "REQUIRED"),
    _field("corpus_id", "STRING", "REQUIRED"),
    _field("exported_at", "TIMESTAMP", "REQUIRED"),
    _field("ati_version", "STRING", "REQUIRED"),
    _field("status", "STRING", "REQUIRED"),
    _field("session_count", "INT64", "REQUIRED"),
    _field("feature_count", "INT64", "REQUIRED"),
    _field("feature_family_count", "INT64", "REQUIRED"),
    _field("prevalence", "FLOAT64", "REQUIRED"),
    _field("l2", "FLOAT64", "REQUIRED"),
    _field("seed", "INT64", "REQUIRED"),
    _field("resample_count", "INT64", "REQUIRED"),
    _field("single_class_split_count", "INT64", "REQUIRED"),
    _field("train_holdout_session_overlap_count", "INT64", "REQUIRED"),
    _field("final_temporal_holdout", "STRING"),
    _field("logistic_beats_constant_on_final_temporal_holdout", "BOOL"),
    _field("target_false_positive_rate", "FLOAT64"),
    _field("meets_predeclared_false_positive_rate", "BOOL"),
)
_BASELINE_METRICS_SCHEMA = (
    _field("run_id", "STRING", "REQUIRED"),
    _field("corpus_id", "STRING", "REQUIRED"),
    _field("split_name", "STRING", "REQUIRED"),
    _field("split_kind", "STRING", "REQUIRED"),
    _field("final_temporal_holdout", "BOOL", "REQUIRED"),
    _field("split_status", "STRING", "REQUIRED"),
    _field("model", "STRING", "REQUIRED"),
    _field("train_session_count", "INT64", "REQUIRED"),
    _field("holdout_session_count", "INT64", "REQUIRED"),
    _field("train_prevalence", "FLOAT64"),
    _field("holdout_prevalence", "FLOAT64"),
    _field("threshold", "FLOAT64", "REQUIRED"),
    _field("threshold_source", "STRING", "REQUIRED"),
    _field("true_positive", "INT64", "REQUIRED"),
    _field("false_positive", "INT64", "REQUIRED"),
    _field("true_negative", "INT64", "REQUIRED"),
    _field("false_negative", "INT64", "REQUIRED"),
    _field("precision", "FLOAT64", "REQUIRED"),
    _field("recall", "FLOAT64", "REQUIRED"),
    _field("f1", "FLOAT64", "REQUIRED"),
    _field("accuracy", "FLOAT64", "REQUIRED"),
    _field("brier_score", "FLOAT64", "REQUIRED"),
    _field("false_positive_rate", "FLOAT64"),
    _field("false_negative_rate", "FLOAT64"),
    _field("pr_auc", "FLOAT64"),
    _field("expected_calibration_error", "FLOAT64"),
    _field("pr_auc_ci_lower", "FLOAT64"),
    _field("pr_auc_ci_upper", "FLOAT64"),
    _field("recall_ci_lower", "FLOAT64"),
    _field("recall_ci_upper", "FLOAT64"),
    _field("false_positive_rate_ci_lower", "FLOAT64"),
    _field("false_positive_rate_ci_upper", "FLOAT64"),
    _field("brier_score_ci_lower", "FLOAT64"),
    _field("brier_score_ci_upper", "FLOAT64"),
    _field("logistic_beats_constant", "BOOL"),
)
_ABLATION_SCHEMA = (
    _field("run_id", "STRING", "REQUIRED"),
    _field("corpus_id", "STRING", "REQUIRED"),
    _field("split_name", "STRING", "REQUIRED"),
    _field("removed_feature_family", "STRING", "REQUIRED"),
    _field("status", "STRING", "REQUIRED"),
    _field("removed_feature_count", "INT64"),
    _field("pr_auc", "FLOAT64"),
    _field("pr_auc_delta", "FLOAT64"),
    _field("recall", "FLOAT64"),
    _field("false_positive_rate", "FLOAT64"),
    _field("brier_score", "FLOAT64"),
)
_FEATURE_SUMMARY_SCHEMA = (
    _field("run_id", "STRING", "REQUIRED"),
    _field("corpus_id", "STRING", "REQUIRED"),
    _field("feature_name", "STRING", "REQUIRED"),
    _field("feature_family", "STRING", "REQUIRED"),
    _field("target_class", "STRING", "REQUIRED"),
    _field("session_count", "INT64", "REQUIRED"),
    _field("distinct_value_count", "INT64", "REQUIRED"),
    _field("minimum", "FLOAT64", "REQUIRED"),
    _field("maximum", "FLOAT64", "REQUIRED"),
    _field("mean", "FLOAT64", "REQUIRED"),
)
_COHORT_SCHEMA = (
    _field("run_id", "STRING", "REQUIRED"),
    _field("corpus_id", "STRING", "REQUIRED"),
    _field("dimension", "STRING", "REQUIRED"),
    _field("cohort", "STRING", "REQUIRED"),
    _field("target_class", "STRING", "REQUIRED"),
    _field("session_count", "INT64", "REQUIRED"),
)

SCHEMAS: Mapping[str, tuple[dict[str, str], ...]] = {
    "pf2_run_manifest": _RUN_MANIFEST_SCHEMA,
    "pf2_baseline_metrics": _BASELINE_METRICS_SCHEMA,
    "pf2_baseline_ablations": _ABLATION_SCHEMA,
    "pf2_feature_summary": _FEATURE_SUMMARY_SCHEMA,
    "pf2_cohort_counts": _COHORT_SCHEMA,
}


def _family_of(feature_name: str) -> str:
    for family, members in PF2_FEATURE_FAMILIES.items():
        if feature_name in members:
            return family
    raise PF2ExportError(f"feature {feature_name!r} has no permitted family")


def _interval_bounds(
    intervals: Mapping[str, Any], metric: str
) -> tuple[float | None, float | None]:
    interval = intervals.get(metric)
    if not isinstance(interval, Mapping):
        return None, None
    lower = interval.get("lower")
    upper = interval.get("upper")
    return (
        float(lower) if isinstance(lower, (int, float)) else None,
        float(upper) if isinstance(upper, (int, float)) else None,
    )


def _numeric(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _assert_exportable(rows: Sequence[Mapping[str, Any]], table: str) -> None:
    for row in rows:
        leaked = sorted(set(row) & _PROHIBITED_EXPORT_KEYS)
        if leaked:
            raise PF2ExportError(
                f"table {table!r} would export prohibited column {leaked[0]!r}"
            )


def build_bigquery_export(
    model_rows: Sequence[Mapping[str, Any]],
    report: Mapping[str, Any],
    *,
    run_id: str,
    corpus_id: str,
    exported_at: str,
    ati_version: str,
) -> PF2Export:
    """Flatten one baseline run into aggregate warehouse tables, or fail closed."""

    for value, name in ((run_id, "run_id"), (corpus_id, "corpus_id")):
        if not isinstance(value, str) or not value.strip():
            raise PF2ExportError(f"{name} must be a non-empty string")
    if PF2_TARGET_NAME not in (model_rows[0] if model_rows else {}):
        raise PF2ExportError("model table must carry the automated target")
    try:
        feature_names = assert_pf2_model_table(model_rows)
    except PF2BaselineError as exc:
        raise PF2ExportError(f"model table is not exportable: {exc}") from exc
    if not isinstance(report.get("splits"), list):
        raise PF2ExportError("baseline report must contain a splits list")

    verdict = report.get("verdict")
    firewall = report.get("firewall")
    if not isinstance(verdict, Mapping) or not isinstance(firewall, Mapping):
        raise PF2ExportError("baseline report must contain a verdict and firewall block")

    manifest_row: dict[str, Any] = {
        "run_id": run_id,
        "corpus_id": corpus_id,
        "exported_at": exported_at,
        "ati_version": ati_version,
        "status": report["status"],
        "session_count": report["session_count"],
        "feature_count": report["feature_count"],
        "feature_family_count": report["feature_family_count"],
        "prevalence": report["prevalence"],
        "l2": report["l2"],
        "seed": report["seed"],
        "resample_count": report["resample_count"],
        "single_class_split_count": firewall["single_class_split_count"],
        "train_holdout_session_overlap_count": firewall[
            "train_holdout_session_overlap_count"
        ],
        "final_temporal_holdout": verdict["final_temporal_holdout"],
        "logistic_beats_constant_on_final_temporal_holdout": verdict[
            "logistic_beats_constant_on_final_temporal_holdout"
        ],
        "target_false_positive_rate": verdict["target_false_positive_rate"],
        "meets_predeclared_false_positive_rate": verdict[
            "meets_predeclared_false_positive_rate"
        ],
    }

    metric_rows: list[dict[str, Any]] = []
    ablation_rows: list[dict[str, Any]] = []
    for split in report["splits"]:
        common = {
            "run_id": run_id,
            "corpus_id": corpus_id,
            "split_name": split["name"],
            "split_kind": split["kind"],
            "final_temporal_holdout": bool(split["final_temporal_holdout"]),
            "split_status": split["status"],
        }
        for model_name, metrics in split["models"].items():
            intervals = metrics.get("session_cluster_intervals", {})
            row = {
                **common,
                "model": model_name,
                "train_session_count": split["train_session_count"],
                "holdout_session_count": split["holdout_session_count"],
                "train_prevalence": _numeric(split["train_prevalence"]),
                "holdout_prevalence": _numeric(split["holdout_prevalence"]),
                "threshold": metrics["threshold"],
                "threshold_source": metrics["threshold_source"],
                "true_positive": metrics["true_positive"],
                "false_positive": metrics["false_positive"],
                "true_negative": metrics["true_negative"],
                "false_negative": metrics["false_negative"],
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1"],
                "accuracy": metrics["accuracy"],
                "brier_score": metrics["brier_score"],
                "false_positive_rate": _numeric(metrics["false_positive_rate"]),
                "false_negative_rate": _numeric(metrics["false_negative_rate"]),
                "pr_auc": _numeric(metrics["pr_auc"]),
                "expected_calibration_error": _numeric(
                    metrics["expected_calibration_error"]
                ),
                "logistic_beats_constant": split["logistic_beats_constant"],
            }
            for metric in _INTERVAL_METRICS:
                lower, upper = _interval_bounds(intervals, metric)
                row[f"{metric}_ci_lower"] = lower
                row[f"{metric}_ci_upper"] = upper
            metric_rows.append(row)
        for family, ablation in split["ablations"].items():
            ablation_rows.append(
                {
                    "run_id": run_id,
                    "corpus_id": corpus_id,
                    "split_name": split["name"],
                    "removed_feature_family": family,
                    "status": ablation["status"],
                    "removed_feature_count": ablation.get("removed_feature_count"),
                    "pr_auc": _numeric(ablation.get("pr_auc")),
                    "pr_auc_delta": _numeric(ablation.get("pr_auc_delta")),
                    "recall": _numeric(ablation.get("recall")),
                    "false_positive_rate": _numeric(ablation.get("false_positive_rate")),
                    "brier_score": _numeric(ablation.get("brier_score")),
                }
            )

    feature_rows: list[dict[str, Any]] = []
    for target_class, wanted in (("automated", True), ("human_assisted", False)):
        selected = [row for row in model_rows if bool(row[PF2_TARGET_NAME]) is wanted]
        if not selected:
            continue
        for feature_name in feature_names:
            values = [float(row[feature_name]) for row in selected]
            feature_rows.append(
                {
                    "run_id": run_id,
                    "corpus_id": corpus_id,
                    "feature_name": feature_name,
                    "feature_family": _family_of(feature_name),
                    "target_class": target_class,
                    "session_count": len(values),
                    "distinct_value_count": len(set(values)),
                    "minimum": min(values),
                    "maximum": max(values),
                    "mean": math.fsum(values) / len(values),
                }
            )

    cohort_rows: list[dict[str, Any]] = []
    cohorts = report.get("cohorts")
    if isinstance(cohorts, Mapping):
        for dimension, buckets in cohorts.items():
            if not isinstance(buckets, Mapping):
                continue
            for cohort, counts in buckets.items():
                for target_class, session_count in counts.items():
                    cohort_rows.append(
                        {
                            "run_id": run_id,
                            "corpus_id": corpus_id,
                            "dimension": dimension,
                            "cohort": cohort,
                            "target_class": target_class,
                            "session_count": session_count,
                        }
                    )

    tables = {
        "pf2_run_manifest": (manifest_row,),
        "pf2_baseline_metrics": tuple(metric_rows),
        "pf2_baseline_ablations": tuple(ablation_rows),
        "pf2_feature_summary": tuple(feature_rows),
        "pf2_cohort_counts": tuple(cohort_rows),
    }
    for name, rows in tables.items():
        _assert_exportable(rows, name)
        declared = {field["name"] for field in SCHEMAS[name]}
        for row in rows:
            undeclared = sorted(set(row) - declared)
            if undeclared:
                raise PF2ExportError(
                    f"table {name!r} row has undeclared column {undeclared[0]!r}"
                )
    return PF2Export(tables=dict(tables), schemas=dict(SCHEMAS))


def bigquery_ddl(dataset: str, *, project: str | None = None) -> str:
    """Render CREATE TABLE IF NOT EXISTS statements for the export tables."""

    if not dataset or not dataset.replace("_", "").isalnum():
        raise PF2ExportError("dataset must be an alphanumeric BigQuery dataset name")
    if project is not None and not project.replace("-", "").replace("_", "").isalnum():
        raise PF2ExportError("project must be a valid BigQuery project identifier")
    qualifier = f"`{project}.{dataset}`" if project else f"`{dataset}`"
    statements: list[str] = []
    for name, fields in SCHEMAS.items():
        columns = ",\n".join(
            f"  {field['name']} {field['type']}"
            + (" NOT NULL" if field["mode"] == "REQUIRED" else "")
            for field in fields
        )
        statements.append(
            f"CREATE TABLE IF NOT EXISTS {qualifier}.{name} (\n{columns}\n);"
        )
    return "\n\n".join(statements) + "\n"
