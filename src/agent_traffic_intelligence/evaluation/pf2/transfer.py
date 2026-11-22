"""Transfer evaluation: train against one adversary, score sessions from another.

The baseline ladder fits and scores on one corpus, so the automation it is tested on is
the automation it was trained on. A deployed detector meets automation it has never seen.
This module trains on one synthetic matched corpus and scores a second one, built with
different people and a different adversary, so it measures what survives that shift.

Three scores are compared:

- `l2_logistic_regression`, the ladder's learned rung, refitted on the whole training
  corpus. It learns which direction separates the training classes, and extrapolates that
  direction to anything it has not seen.
- `human_reference`, which learns only what the training corpus's people do: for each
  regime-invariant behaviour feature, the share of people with each value, with Laplace
  smoothing. A session scores by how unlikely its values are among people, so it is
  flagged for departing from people in either direction.
- `combined`, each of the two as its percentile among the training corpus's people,
  taking the larger: a session is as suspicious as its more suspicious score says.

Each score is reported as the area under the ROC curve for telling the test corpus's
automation from its people. Below 0.5 means the score ranks the automation as more
human than the people. Everything here is synthetic.
"""

from __future__ import annotations

import bisect
import math
import statistics
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from agent_traffic_intelligence.evaluation.pf2.baseline import _fit_logistic, _predict
from agent_traffic_intelligence.evaluation.pf2.protocol import (
    PF2_FEATURE_FAMILIES,
    PF2_TARGET_NAME,
    pf2_feature_names,
    prepare_pf2_dataset,
)
from agent_traffic_intelligence.evaluation.pf2.simulation import (
    AutomationPauseModel,
    HumanPauseModel,
    SimulatedCorpus,
    SimulatedScenario,
    simulate_matched_corpus,
)

REFERENCE_FAMILIES = ("tempo_shape", "content_tempo")
"""Families the human reference reads. Both are scale-free, so they do not depend on
which pacing regime a session followed, only on how it behaved within it."""
SCORES = ("l2_logistic_regression", "human_reference", "combined")
_L2 = 1.0
_TEST_SEED_OFFSET = 500_000


def auc(scores: Sequence[float], automated: Sequence[bool]) -> float:
    """Probability that an automated session outscores a person, ties counting one half."""

    positives = [score for score, label in zip(scores, automated, strict=True) if label]
    negatives = [score for score, label in zip(scores, automated, strict=True) if not label]
    if not positives or not negatives:
        raise ValueError("both classes are needed to compute an AUC")
    wins = sum((p > n) + 0.5 * (p == n) for p in positives for n in negatives)
    return wins / (len(positives) * len(negatives))


def human_reference(
    train_rows: Sequence[Mapping[str, Any]], feature_names: Sequence[str]
) -> Callable[[Mapping[str, Any]], float]:
    """Return a scorer: minus the log-likelihood of a session's values among people."""

    people = [row for row in train_rows if not row[PF2_TARGET_NAME]]
    if not people:
        raise ValueError("the training corpus has no people to learn from")
    tables = []
    for name in feature_names:
        counts = Counter(int(row[name]) for row in people)
        # One extra level stands for every value no person showed.
        tables.append((name, counts, len(people) + len(counts) + 1))

    def score(row: Mapping[str, Any]) -> float:
        return -math.fsum(
            math.log((counts.get(int(row[name]), 0) + 1) / denominator)
            for name, counts, denominator in tables
        )

    return score


def _percentile(reference: Sequence[float]) -> Callable[[float], float]:
    ordered = sorted(reference)
    return lambda value: bisect.bisect_right(ordered, value) / len(ordered)


def _design(rows: Sequence[Mapping[str, Any]], names: Sequence[str]) -> list[list[float]]:
    return [[float(row[name]) for name in names] for row in rows]


def score_transfer(
    train_rows: Sequence[Mapping[str, Any]], test_rows: Sequence[Mapping[str, Any]]
) -> dict[str, float]:
    """Fit on `train_rows` and return each score's AUC on `test_rows`."""

    names = pf2_feature_names()
    train_labels = [bool(row[PF2_TARGET_NAME]) for row in train_rows]
    test_labels = [bool(row[PF2_TARGET_NAME]) for row in test_rows]
    fitted = _fit_logistic(_design(train_rows, names), train_labels, names, l2=_L2)
    reference = human_reference(
        train_rows, [name for family in REFERENCE_FAMILIES for name in PF2_FEATURE_FAMILIES[family]]
    )
    people = [row for row, label in zip(train_rows, train_labels, strict=True) if not label]
    logistic_rank = _percentile(_predict(fitted, _design(people, names)))
    reference_rank = _percentile([reference(row) for row in people])

    logistic = _predict(fitted, _design(test_rows, names))
    referenced = [reference(row) for row in test_rows]
    combined = [
        max(logistic_rank(first), reference_rank(second))
        for first, second in zip(logistic, referenced, strict=True)
    ]
    return {
        "l2_logistic_regression": auc(logistic, test_labels),
        "human_reference": auc(referenced, test_labels),
        "combined": auc(combined, test_labels),
    }


def _model_rows(corpus: SimulatedCorpus) -> list[dict[str, Any]]:
    prepared = prepare_pf2_dataset(
        corpus.records,
        labels_by_session=corpus.labels,
        task_by_session=corpus.tasks,
        collection_window_by_session=corpus.windows,
        group_by_session=corpus.groups,
        min_sessions_per_task_class=1,
    )
    return [dict(row) for row in prepared.model_rows]


def plan_transfer(
    *,
    human_model: HumanPauseModel,
    sessions_per_cell: int,
    participants: int,
    train_automation_model: AutomationPauseModel,
    test_automation_model: AutomationPauseModel,
    train_imitation_fidelity: float = 0.0,
    test_imitation_fidelity: float = 0.0,
    scenario: SimulatedScenario = SimulatedScenario.READING,
    repeats: int = 20,
    seed: int = 0,
) -> dict[str, Any]:
    """Train on one adversary and test on another, `repeats` times, with new people."""

    if repeats < 1:
        raise ValueError("repeats must be positive")
    results: dict[str, list[float]] = {name: [] for name in SCORES}
    for repeat in range(repeats):
        base = seed * 1_000_003 + repeat
        train = simulate_matched_corpus(
            human_model=human_model,
            sessions_per_cell=sessions_per_cell,
            participants=participants,
            seed=base,
            automation_model=train_automation_model,
            imitation_fidelity=train_imitation_fidelity,
            scenario=scenario,
        )
        test = simulate_matched_corpus(
            human_model=human_model,
            sessions_per_cell=sessions_per_cell,
            participants=participants,
            seed=base + _TEST_SEED_OFFSET,
            automation_model=test_automation_model,
            imitation_fidelity=test_imitation_fidelity,
            scenario=scenario,
        )
        for name, value in score_transfer(_model_rows(train), _model_rows(test)).items():
            results[name].append(value)
    return {
        "fixture": True,
        "scenario": scenario.value,
        "human_model": human_model.value,
        "participants": participants,
        "sessions_per_cell": sessions_per_cell,
        "train": {
            "automation_model": train_automation_model.value,
            "imitation_fidelity": train_imitation_fidelity,
        },
        "test": {
            "automation_model": test_automation_model.value,
            "imitation_fidelity": test_imitation_fidelity,
        },
        "repeats": repeats,
        "seed": seed,
        "scores": {
            name: {
                "mean_auc": round(statistics.fmean(values), 3),
                "min_auc": round(min(values), 3),
                "inverted_rate": sum(value < 0.5 for value in values) / len(values),
            }
            for name, values in results.items()
        },
    }
