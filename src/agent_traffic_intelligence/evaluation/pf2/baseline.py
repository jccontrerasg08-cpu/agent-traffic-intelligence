"""Privacy-first baseline ladder for the ATI-PF-2 laboratory protocol.

This module consumes the two separate artifacts produced by the ATI-PF-2 preflight: a
model table that holds only the target and the predeclared coarse features, and a split
manifest that holds only opaque session pseudonyms plus audit-only task and collection
window labels. The split manifest is used exclusively to build partitions; no column of
it ever reaches an estimator, a scaler, a threshold search or an ablation.

The ladder implements the controlled-corpus feature contract in order: a non-model
constant-prevalence classifier first, then one regularized logistic regression over the
permitted feature families only. Standardization statistics, coefficients and the
operating threshold are derived inside the training partition of each split. Uncertainty
is reported with session-cluster resampling; the ATI-PF-2 model table holds exactly one
row per opaque session, so resampling rows is session-cluster resampling by construction.

Nothing here establishes generalization to public traffic, a population false-positive
rate, calibrated probabilities or an enforcement threshold.
"""

from __future__ import annotations

import math
import random
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agent_traffic_intelligence.evaluation.metrics import expected_calibration_error, pr_auc
from agent_traffic_intelligence.evaluation.pf2.protocol import (
    PF2_FEATURE_FAMILIES,
    PF2_TARGET_NAME,
    is_pf2_session_id,
    pf2_feature_names,
)

_SPLIT_FIELDS = frozenset({"row_index", "session_id", "task", "collection_window"})
_CONSTANT_MODEL = "constant_prevalence"
_LOGISTIC_MODEL = "l2_logistic_regression"
_INTERVAL_METRICS = ("recall", "false_positive_rate", "pr_auc", "brier_score")
_DEFAULT_RESAMPLES = 1000
_DEFAULT_L2 = 1.0
_MAX_NEWTON_ITERATIONS = 100
_NEWTON_TOLERANCE = 1e-9
_MAX_STEP_HALVINGS = 30
_MIN_WEIGHT = 1e-9


class PF2BaselineError(ValueError):
    """Raised when a controlled corpus cannot support an auditable PF-2 baseline."""


@dataclass(frozen=True, slots=True)
class PF2Split:
    """One fail-closed holdout built only from audit-only split metadata."""

    name: str
    kind: str
    train_rows: tuple[int, ...]
    holdout_rows: tuple[int, ...]
    final_temporal_holdout: bool = False


@dataclass(frozen=True, slots=True)
class PF2BaselineReport:
    """Ladder results, firewall assertions and one overall readiness status."""

    report: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return dict(self.report)


def _sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-value))
    exponential = math.exp(value)
    return exponential / (1.0 + exponential)


def _log_sigmoid(value: float) -> float:
    if value >= 0:
        return -math.log1p(math.exp(-value))
    return value - math.log1p(math.exp(value))


def assert_pf2_model_table(rows: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    """Assert a model table carries only permitted columns and return the vocabulary."""

    return _validate_model_rows(rows)


def _validate_model_rows(rows: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    """Reject any column outside the permitted ATI-PF-2 vocabulary."""

    if not rows:
        raise PF2BaselineError("model table must contain at least one session row")
    feature_names = pf2_feature_names()
    permitted = set(feature_names) | {PF2_TARGET_NAME}
    for row in rows:
        prohibited = sorted(set(row) - permitted)
        if prohibited:
            raise PF2BaselineError(
                f"model table contains prohibited column {prohibited[0]!r}"
            )
        if PF2_TARGET_NAME not in row:
            raise PF2BaselineError("model table row is missing the automated target")
        if not isinstance(row[PF2_TARGET_NAME], bool):
            raise PF2BaselineError("model table target must be a boolean")
        for name in feature_names:
            if name not in row:
                raise PF2BaselineError(f"model table row is missing feature {name!r}")
            value = row[name]
            if isinstance(value, bool):
                continue
            if not isinstance(value, int):
                raise PF2BaselineError(
                    f"model table feature {name!r} must be an integer or boolean"
                )
    return feature_names


def _validate_split_rows(
    split_rows: Sequence[Mapping[str, Any]], *, row_count: int
) -> tuple[dict[int, str], dict[int, str], dict[int, str | None]]:
    """Reject split metadata that cannot support a leakage-controlled partition."""

    if len(split_rows) != row_count:
        raise PF2BaselineError("split manifest must describe every model table row exactly once")
    sessions: dict[int, str] = {}
    tasks: dict[int, str] = {}
    windows: dict[int, str | None] = {}
    seen_sessions: set[str] = set()
    for row in split_rows:
        prohibited = sorted(set(row) - _SPLIT_FIELDS)
        if prohibited:
            raise PF2BaselineError(f"split manifest contains unsupported field {prohibited[0]!r}")
        row_index = row.get("row_index")
        if isinstance(row_index, bool) or not isinstance(row_index, int):
            raise PF2BaselineError("split manifest row_index must be an integer")
        if not 0 <= row_index < row_count:
            raise PF2BaselineError("split manifest row_index is outside the model table")
        if row_index in sessions:
            raise PF2BaselineError("split manifest contains a duplicate row_index")
        session_id = row.get("session_id")
        if not is_pf2_session_id(session_id):
            raise PF2BaselineError("split manifest session_id must be an opaque HMAC pseudonym")
        assert isinstance(session_id, str)
        if session_id in seen_sessions:
            raise PF2BaselineError("split manifest contains a duplicate session pseudonym")
        seen_sessions.add(session_id)
        task = row.get("task")
        if not isinstance(task, str) or not task.strip():
            raise PF2BaselineError("split manifest task must be a non-empty audit label")
        window = row.get("collection_window")
        if window is not None and (not isinstance(window, str) or not window.strip()):
            raise PF2BaselineError(
                "split manifest collection_window must be a non-empty audit label"
            )
        sessions[row_index] = session_id
        tasks[row_index] = task
        windows[row_index] = window
    return sessions, tasks, windows


def build_pf2_splits(
    tasks: Mapping[int, str],
    windows: Mapping[int, str | None],
    *,
    grouped_holdout_fraction: float = 0.25,
    seed: int = 0,
) -> tuple[PF2Split, ...]:
    """Build forward-chained temporal, leave-one-task-out and grouped session holdouts.

    Temporal splits never train on a later collection window, so the earliest window is
    never a holdout. The last window in sorted order is the final temporal holdout.
    """

    if not 0.0 < grouped_holdout_fraction < 1.0:
        raise PF2BaselineError("grouped_holdout_fraction must be between 0 and 1")
    splits: list[PF2Split] = []

    ordered_windows = sorted({window for window in windows.values() if window is not None})
    for position, window in enumerate(ordered_windows):
        if position == 0:
            continue
        earlier = {ordered_windows[index] for index in range(position)}
        train_rows = tuple(
            sorted(row for row, value in windows.items() if value in earlier)
        )
        holdout_rows = tuple(sorted(row for row, value in windows.items() if value == window))
        splits.append(
            PF2Split(
                name=f"temporal:{window}",
                kind="temporal",
                train_rows=train_rows,
                holdout_rows=holdout_rows,
                final_temporal_holdout=position == len(ordered_windows) - 1,
            )
        )

    for task in sorted(set(tasks.values())):
        holdout_rows = tuple(sorted(row for row, value in tasks.items() if value == task))
        train_rows = tuple(sorted(row for row, value in tasks.items() if value != task))
        splits.append(
            PF2Split(
                name=f"task:{task}",
                kind="unseen_task",
                train_rows=train_rows,
                holdout_rows=holdout_rows,
            )
        )

    ordered_rows = sorted(tasks)
    shuffled = list(ordered_rows)
    random.Random(seed).shuffle(shuffled)
    holdout_size = max(1, round(len(shuffled) * grouped_holdout_fraction))
    holdout_rows = tuple(sorted(shuffled[:holdout_size]))
    train_rows = tuple(sorted(shuffled[holdout_size:]))
    splits.append(
        PF2Split(
            name="grouped_session:holdout",
            kind="grouped_session",
            train_rows=train_rows,
            holdout_rows=holdout_rows,
        )
    )
    return tuple(splits)


def _solve(matrix: list[list[float]], vector: list[float]) -> list[float]:
    """Solve a dense linear system with partial pivoting; fail closed when singular."""

    size = len(vector)
    augmented = [[*matrix[row], vector[row]] for row in range(size)]
    for column in range(size):
        pivot_row = max(range(column, size), key=lambda row: abs(augmented[row][column]))
        if abs(augmented[pivot_row][column]) < 1e-12:
            raise PF2BaselineError("logistic regression system is numerically singular")
        augmented[column], augmented[pivot_row] = augmented[pivot_row], augmented[column]
        pivot = augmented[column][column]
        for row in range(column + 1, size):
            factor = augmented[row][column] / pivot
            if factor:
                for position in range(column, size + 1):
                    augmented[row][position] -= factor * augmented[column][position]
    solution = [0.0] * size
    for row in reversed(range(size)):
        total = augmented[row][size] - sum(
            augmented[row][column] * solution[column] for column in range(row + 1, size)
        )
        solution[row] = total / augmented[row][row]
    return solution


@dataclass(frozen=True, slots=True)
class _Fitted:
    """Coefficients plus the training-partition statistics used to standardize inputs."""

    feature_names: tuple[str, ...]
    intercept: float
    coefficients: tuple[float, ...]
    centers: tuple[float, ...]
    scales: tuple[float, ...]
    iterations: int
    converged: bool


def _design(
    rows: Sequence[Mapping[str, Any]],
    row_indexes: Sequence[int],
    feature_names: Sequence[str],
) -> list[list[float]]:
    return [
        [float(rows[row_index][name]) for name in feature_names] for row_index in row_indexes
    ]


def _targets(rows: Sequence[Mapping[str, Any]], row_indexes: Sequence[int]) -> list[bool]:
    return [bool(rows[row_index][PF2_TARGET_NAME]) for row_index in row_indexes]


def _standardization(design: Sequence[Sequence[float]]) -> tuple[list[float], list[float]]:
    sample_count = len(design)
    feature_count = len(design[0]) if design else 0
    centers: list[float] = []
    scales: list[float] = []
    for column in range(feature_count):
        values = [row[column] for row in design]
        center = math.fsum(values) / sample_count
        variance = math.fsum((value - center) ** 2 for value in values) / sample_count
        deviation = math.sqrt(variance)
        centers.append(center)
        scales.append(deviation if deviation > 1e-12 else 1.0)
    return centers, scales


def _standardize(
    design: Sequence[Sequence[float]], centers: Sequence[float], scales: Sequence[float]
) -> list[list[float]]:
    return [
        [1.0, *((value - centers[column]) / scales[column] for column, value in enumerate(row))]
        for row in design
    ]


def _penalized_log_likelihood(
    matrix: Sequence[Sequence[float]],
    targets: Sequence[bool],
    beta: Sequence[float],
    l2: float,
) -> float:
    total = 0.0
    for row, target in zip(matrix, targets, strict=True):
        linear = math.fsum(
            value * coefficient for value, coefficient in zip(row, beta, strict=True)
        )
        total += _log_sigmoid(linear) if target else _log_sigmoid(-linear)
    penalty = l2 * math.fsum(coefficient**2 for coefficient in beta[1:])
    return total - penalty


def _fit_logistic(
    design: Sequence[Sequence[float]],
    targets: Sequence[bool],
    feature_names: Sequence[str],
    *,
    l2: float,
) -> _Fitted:
    """Fit an L2-penalized logistic regression with damped Newton steps."""

    if len(set(targets)) < 2:
        raise PF2BaselineError("logistic regression requires both classes in the train partition")
    centers, scales = _standardization(design)
    matrix = _standardize(design, centers, scales)
    parameter_count = len(matrix[0])
    beta = [0.0] * parameter_count
    objective = _penalized_log_likelihood(matrix, targets, beta, l2)
    iterations = 0
    converged = False
    for iterations in range(1, _MAX_NEWTON_ITERATIONS + 1):  # noqa: B007
        probabilities = [
            _sigmoid(
                math.fsum(value * coefficient for value, coefficient in zip(row, beta, strict=True))
            )
            for row in matrix
        ]
        gradient = [0.0] * parameter_count
        for row, target, probability in zip(matrix, targets, probabilities, strict=True):
            residual = (1.0 if target else 0.0) - probability
            for column in range(parameter_count):
                gradient[column] += row[column] * residual
        for column in range(1, parameter_count):
            gradient[column] -= 2.0 * l2 * beta[column]
        hessian = [[0.0] * parameter_count for _ in range(parameter_count)]
        for row, probability in zip(matrix, probabilities, strict=True):
            weight = max(probability * (1.0 - probability), _MIN_WEIGHT)
            for first in range(parameter_count):
                weighted = weight * row[first]
                for second in range(first, parameter_count):
                    hessian[first][second] += weighted * row[second]
        for first in range(parameter_count):
            for second in range(first):
                hessian[first][second] = hessian[second][first]
        for column in range(1, parameter_count):
            hessian[column][column] += 2.0 * l2
        step = _solve(hessian, gradient)
        scale = 1.0
        candidate = list(beta)
        candidate_objective = objective
        for _ in range(_MAX_STEP_HALVINGS):
            candidate = [
                coefficient + scale * increment
                for coefficient, increment in zip(beta, step, strict=True)
            ]
            candidate_objective = _penalized_log_likelihood(matrix, targets, candidate, l2)
            if candidate_objective >= objective:
                break
            scale /= 2.0
        else:
            # No damped step improves the penalized objective, so the current
            # coefficients are a stationary point at this numerical resolution.
            converged = True
            break
        change = max(abs(scale * increment) for increment in step)
        beta = candidate
        objective = candidate_objective
        if change < _NEWTON_TOLERANCE:
            converged = True
            break
    return _Fitted(
        feature_names=tuple(feature_names),
        intercept=beta[0],
        coefficients=tuple(beta[1:]),
        centers=tuple(centers),
        scales=tuple(scales),
        iterations=iterations,
        converged=converged,
    )


def _predict(fitted: _Fitted, design: Sequence[Sequence[float]]) -> list[float]:
    return [
        _sigmoid(
            fitted.intercept
            + math.fsum(
                coefficient * (value - center) / scale
                for coefficient, value, center, scale in zip(
                    fitted.coefficients, row, fitted.centers, fitted.scales, strict=True
                )
            )
        )
        for row in design
    ]


def _threshold_for_target_false_positive_rate(
    scores: Sequence[float], targets: Sequence[bool], target_rate: float
) -> float:
    """Choose the lowest train-partition threshold whose train FPR meets the target."""

    negatives = [score for score, target in zip(scores, targets, strict=True) if not target]
    if not negatives:
        return 0.5
    candidates = sorted({*scores, 0.0, 1.0})
    for candidate in candidates:
        false_positives = sum(score >= candidate for score in negatives)
        if false_positives / len(negatives) <= target_rate:
            return candidate
    return math.nextafter(1.0, math.inf)


def _metrics(
    scores: Sequence[float], targets: Sequence[bool], *, threshold: float
) -> dict[str, Any]:
    true_positive = false_positive = true_negative = false_negative = 0
    for score, target in zip(scores, targets, strict=True):
        predicted = score >= threshold
        if target and predicted:
            true_positive += 1
        elif target:
            false_negative += 1
        elif predicted:
            false_positive += 1
        else:
            true_negative += 1
    positives = true_positive + false_negative
    negatives = true_negative + false_positive
    predicted_positives = true_positive + false_positive
    precision = true_positive / predicted_positives if predicted_positives else 0.0
    recall = true_positive / positives if positives else 0.0
    scored_labels = [(score, target) for score, target in zip(scores, targets, strict=True)]
    return {
        "threshold": threshold,
        "session_count": len(scored_labels),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "precision": precision,
        "recall": recall,
        "f1": (
            2 * precision * recall / (precision + recall) if precision + recall else 0.0
        ),
        "accuracy": (true_positive + true_negative) / len(scored_labels),
        "brier_score": math.fsum(
            (score - (1.0 if target else 0.0)) ** 2 for score, target in scored_labels
        )
        / len(scored_labels),
        "false_positive_rate": false_positive / negatives if negatives else None,
        "false_negative_rate": false_negative / positives if positives else None,
        "pr_auc": pr_auc(scored_labels),
        "expected_calibration_error": expected_calibration_error(scored_labels),
    }


def _session_cluster_intervals(
    scores: Sequence[float],
    targets: Sequence[bool],
    *,
    threshold: float,
    resamples: int,
    seed: int,
) -> dict[str, dict[str, float | int] | None]:
    """Percentile intervals from resampling opaque sessions with replacement."""

    generator = random.Random(seed)
    collected: dict[str, list[float]] = {metric: [] for metric in _INTERVAL_METRICS}
    sample_count = len(scores)
    for _ in range(resamples):
        picks = [generator.randrange(sample_count) for _ in range(sample_count)]
        resampled_scores = [scores[index] for index in picks]
        resampled_targets = [targets[index] for index in picks]
        resampled = _metrics(resampled_scores, resampled_targets, threshold=threshold)
        for metric in _INTERVAL_METRICS:
            value = resampled[metric]
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                collected[metric].append(float(value))
    intervals: dict[str, dict[str, float | int] | None] = {}
    for metric, values in collected.items():
        if len(values) < 2:
            intervals[metric] = None
            continue
        values.sort()
        intervals[metric] = {
            "lower": values[max(0, math.floor(0.025 * (len(values) - 1)))],
            "upper": values[min(len(values) - 1, math.ceil(0.975 * (len(values) - 1)))],
            "resample_count": len(values),
        }
    return intervals


def _evaluate_model(
    scores_train: Sequence[float],
    targets_train: Sequence[bool],
    scores_holdout: Sequence[float],
    targets_holdout: Sequence[bool],
    *,
    target_false_positive_rate: float | None,
    resamples: int,
    seed: int,
) -> dict[str, Any]:
    threshold = (
        0.5
        if target_false_positive_rate is None
        else _threshold_for_target_false_positive_rate(
            scores_train, targets_train, target_false_positive_rate
        )
    )
    result = _metrics(scores_holdout, targets_holdout, threshold=threshold)
    result["threshold_source"] = (
        "fixed-0.5" if target_false_positive_rate is None else "train-partition-target-fpr"
    )
    result["session_cluster_intervals"] = _session_cluster_intervals(
        scores_holdout,
        targets_holdout,
        threshold=threshold,
        resamples=resamples,
        seed=seed,
    )
    return result


def _beats_baseline(
    logistic: Mapping[str, Any], constant: Mapping[str, Any]
) -> bool | None:
    """Require a point-estimate win whose session-cluster lower bound clears the baseline."""

    logistic_auc = logistic["pr_auc"]
    constant_auc = constant["pr_auc"]
    if logistic_auc is None or constant_auc is None:
        return None
    interval = logistic["session_cluster_intervals"]["pr_auc"]
    if interval is None:
        return None
    return bool(logistic_auc > constant_auc and interval["lower"] > constant_auc)


def evaluate_pf2_baseline(
    model_rows: Iterable[Mapping[str, Any]],
    split_rows: Iterable[Mapping[str, Any]],
    *,
    l2: float = _DEFAULT_L2,
    target_false_positive_rate: float | None = None,
    resamples: int = _DEFAULT_RESAMPLES,
    seed: int = 0,
    grouped_holdout_fraction: float = 0.25,
) -> PF2BaselineReport:
    """Run the constant-prevalence and regularized-logistic ladder over fixed holdouts."""

    if l2 <= 0:
        raise PF2BaselineError("l2 must be positive so the baseline stays regularized")
    if resamples < 2:
        raise PF2BaselineError("resamples must be at least 2 for a session-cluster interval")
    if target_false_positive_rate is not None and not 0.0 <= target_false_positive_rate <= 1.0:
        raise PF2BaselineError("target_false_positive_rate must be between 0 and 1")

    rows = [dict(row) for row in model_rows]
    feature_names = _validate_model_rows(rows)
    manifest = [dict(row) for row in split_rows]
    _, tasks, windows = _validate_split_rows(manifest, row_count=len(rows))

    all_targets = _targets(rows, sorted(tasks))
    if len(set(all_targets)) < 2:
        raise PF2BaselineError("model table must contain both classes")

    splits = build_pf2_splits(
        tasks,
        windows,
        grouped_holdout_fraction=grouped_holdout_fraction,
        seed=seed,
    )
    inventory = {
        name: {
            "distinct_value_count": len({row[name] for row in rows}),
            "missing_value_count": sum(name not in row for row in rows),
        }
        for name in feature_names
    }
    cohorts = {
        "task": _cohort_counts(tasks, rows),
        "collection_window": _cohort_counts(
            {row: window for row, window in windows.items() if window is not None}, rows
        ),
    }

    split_reports: list[dict[str, Any]] = []
    single_class_split_count = 0
    overlap_count = 0
    for split in splits:
        overlap = set(split.train_rows) & set(split.holdout_rows)
        overlap_count += len(overlap)
        if overlap:
            raise PF2BaselineError(
                f"split {split.name!r} places the same opaque session in train and holdout"
            )
        train_targets = _targets(rows, split.train_rows)
        holdout_targets = _targets(rows, split.holdout_rows)
        entry: dict[str, Any] = {
            "name": split.name,
            "kind": split.kind,
            "final_temporal_holdout": split.final_temporal_holdout,
            "train_session_count": len(split.train_rows),
            "holdout_session_count": len(split.holdout_rows),
            "train_prevalence": (
                sum(train_targets) / len(train_targets) if train_targets else None
            ),
            "holdout_prevalence": (
                sum(holdout_targets) / len(holdout_targets) if holdout_targets else None
            ),
        }
        if len(set(train_targets)) < 2 or len(set(holdout_targets)) < 2:
            single_class_split_count += 1
            entry["status"] = "blocked-single-class"
            entry["models"] = {}
            entry["ablations"] = {}
            entry["logistic_beats_constant"] = None
            split_reports.append(entry)
            continue

        train_design = _design(rows, split.train_rows, feature_names)
        holdout_design = _design(rows, split.holdout_rows, feature_names)
        prevalence = sum(train_targets) / len(train_targets)
        constant = _evaluate_model(
            [prevalence] * len(train_targets),
            train_targets,
            [prevalence] * len(holdout_targets),
            holdout_targets,
            target_false_positive_rate=target_false_positive_rate,
            resamples=resamples,
            seed=seed,
        )
        fitted = _fit_logistic(train_design, train_targets, feature_names, l2=l2)
        logistic = _evaluate_model(
            _predict(fitted, train_design),
            train_targets,
            _predict(fitted, holdout_design),
            holdout_targets,
            target_false_positive_rate=target_false_positive_rate,
            resamples=resamples,
            seed=seed,
        )
        logistic["converged"] = fitted.converged
        logistic["newton_iterations"] = fitted.iterations
        entry["status"] = "evaluated"
        entry["models"] = {_CONSTANT_MODEL: constant, _LOGISTIC_MODEL: logistic}
        entry["ablations"] = _ablations(
            rows,
            split,
            feature_names,
            train_targets=train_targets,
            holdout_targets=holdout_targets,
            full_model=logistic,
            l2=l2,
            target_false_positive_rate=target_false_positive_rate,
            resamples=resamples,
            seed=seed,
        )
        entry["logistic_beats_constant"] = _beats_baseline(logistic, constant)
        split_reports.append(entry)

    final_temporal = next(
        (entry for entry in split_reports if entry["final_temporal_holdout"]), None
    )
    status = (
        "blocked-single-class-split"
        if single_class_split_count
        else "blocked-no-temporal-holdout"
        if final_temporal is None
        else "evaluated"
    )
    verdict = _verdict(final_temporal, target_false_positive_rate)
    report: dict[str, Any] = {
        "status": status,
        "session_count": len(rows),
        "feature_count": len(feature_names),
        "feature_family_count": len(PF2_FEATURE_FAMILIES),
        "prevalence": sum(all_targets) / len(all_targets),
        "l2": l2,
        "seed": seed,
        "resample_count": resamples,
        "firewall": {
            "permitted_feature_count": len(feature_names),
            "prohibited_column_count": 0,
            "duplicate_session_count": 0,
            "train_holdout_session_overlap_count": overlap_count,
            "split_metadata_reached_estimator": False,
            "single_class_split_count": single_class_split_count,
        },
        "feature_inventory": inventory,
        "cohorts": cohorts,
        "splits": split_reports,
        "verdict": verdict,
    }
    return PF2BaselineReport(report=report)


def _cohort_counts(
    labels: Mapping[int, str], rows: Sequence[Mapping[str, Any]]
) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for row_index, label in labels.items():
        bucket = counts.setdefault(label, {"automated": 0, "human_assisted": 0})
        key = "automated" if rows[row_index][PF2_TARGET_NAME] else "human_assisted"
        bucket[key] += 1
    return dict(sorted(counts.items()))


def _ablations(
    rows: Sequence[Mapping[str, Any]],
    split: PF2Split,
    feature_names: Sequence[str],
    *,
    train_targets: Sequence[bool],
    holdout_targets: Sequence[bool],
    full_model: Mapping[str, Any],
    l2: float,
    target_false_positive_rate: float | None,
    resamples: int,
    seed: int,
) -> dict[str, Any]:
    """Refit the permitted model once per removed feature family and report deltas."""

    results: dict[str, Any] = {}
    for family, members in PF2_FEATURE_FAMILIES.items():
        retained = tuple(name for name in feature_names if name not in set(members))
        if not retained:
            results[family] = {"status": "blocked-no-remaining-feature"}
            continue
        train_design = _design(rows, split.train_rows, retained)
        holdout_design = _design(rows, split.holdout_rows, retained)
        fitted = _fit_logistic(train_design, train_targets, retained, l2=l2)
        ablated = _evaluate_model(
            _predict(fitted, train_design),
            train_targets,
            _predict(fitted, holdout_design),
            holdout_targets,
            target_false_positive_rate=target_false_positive_rate,
            resamples=resamples,
            seed=seed,
        )
        results[family] = {
            "status": "evaluated",
            "removed_feature_count": len(feature_names) - len(retained),
            "pr_auc": ablated["pr_auc"],
            "recall": ablated["recall"],
            "false_positive_rate": ablated["false_positive_rate"],
            "brier_score": ablated["brier_score"],
            "pr_auc_delta": (
                None
                if ablated["pr_auc"] is None or full_model["pr_auc"] is None
                else ablated["pr_auc"] - full_model["pr_auc"]
            ),
        }
    return results


def _verdict(
    final_temporal: Mapping[str, Any] | None, target_false_positive_rate: float | None
) -> dict[str, Any]:
    if final_temporal is None or final_temporal["status"] != "evaluated":
        return {
            "final_temporal_holdout": None
            if final_temporal is None
            else final_temporal["name"],
            "logistic_beats_constant_on_final_temporal_holdout": None,
            "target_false_positive_rate": target_false_positive_rate,
            "meets_predeclared_false_positive_rate": None,
        }
    logistic = final_temporal["models"][_LOGISTIC_MODEL]
    observed = logistic["false_positive_rate"]
    return {
        "final_temporal_holdout": final_temporal["name"],
        "logistic_beats_constant_on_final_temporal_holdout": final_temporal[
            "logistic_beats_constant"
        ],
        "target_false_positive_rate": target_false_positive_rate,
        "meets_predeclared_false_positive_rate": (
            None
            if target_false_positive_rate is None or observed is None
            else observed <= target_false_positive_rate
        ),
    }
