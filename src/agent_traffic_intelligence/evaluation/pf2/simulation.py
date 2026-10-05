"""Synthetic matched-executor corpora for planning an ATI-PF-2 collection.

Everything here is a FIXTURE, never traffic. It answers a question that has to be settled
before anyone is recruited: if consenting people pause differently from a timer in a
given way, how many people and sessions would the baseline ladder need to detect it?

The simulated design is the laboratory's matched-executor design. Both cohorts share the
route plan, the tasks, the collection windows and the H1-H3 pacing regimes; automation
draws each pause uniformly from its regime. People differ from one another: each
simulated participant has a personal pace and, for the lognormal model, a personal
irregularity. Each participant is assigned one task and one collection window, so that
the participant-grouped splits can hold people out without emptying a training set.
"""

from __future__ import annotations

import math
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from agent_traffic_intelligence.evaluation.pf2.baseline import evaluate_pf2_baseline
from agent_traffic_intelligence.evaluation.pf2.protocol import prepare_pf2_dataset

SIMULATED_PLANS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        task: (
            "/lab/start",
            "/lab/page/landing",
            "/lab/assets/site.css",
            "/lab/page/catalog",
            "/lab/assets/pixel.svg",
            branch,
            "/lab/complete",
        )
        for task, branch in (
            ("task-detail", "/lab/page/detail"),
            ("task-related", "/lab/page/related"),
        )
    }
)
"""The laboratory executor's two task plans with assets, as `plan_session` builds them."""

PACING_REGIMES: Mapping[str, tuple[float, float]] = MappingProxyType(
    {"H1": (5.0, 12.0), "H2": (12.0, 25.0), "H3": (25.0, 45.0)}
)
"""The pause ranges a person is shown as guidance and a timer draws from."""

SIMULATED_WINDOWS = 3
"""Collection windows per simulated corpus; the last is the final temporal holdout."""

_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
_PERSONAL_PACE_SPREAD = 0.25
_LINGER_PROBABILITY = 0.3


class HumanPauseModel(StrEnum):
    """How a simulated person chooses each pause when shown a regime's range."""

    UNIFORM = "uniform"
    """Indistinguishable from the timer. The ladder must not claim a win against it."""

    LINGER = "linger"
    """Like the timer, except that some pauses run past the range."""

    LOGNORMAL = "lognormal"
    """Aims at the middle of the range with a personal, right-skewed irregularity."""


@dataclass(frozen=True, slots=True)
class SimulatedCorpus:
    """Preflight inputs for one synthetic corpus."""

    records: tuple[dict[str, Any], ...]
    labels: dict[str, bool]
    tasks: dict[str, str]
    windows: dict[str, str]
    groups: dict[str, str]


@dataclass(frozen=True, slots=True)
class _Person:
    code: str
    pace: float
    irregularity: float


def simulate_matched_corpus(
    *,
    human_model: HumanPauseModel,
    sessions_per_cell: int,
    participants: int,
    windows: int = SIMULATED_WINDOWS,
    seed: int = 0,
) -> SimulatedCorpus:
    """Build one corpus with `sessions_per_cell` sessions per task, window, regime and cohort.

    Participants are spread over the task-by-window cells, so there must be at least one
    per cell. A cell's consented sessions rotate among that cell's participants.
    """

    cells = [(task, f"w{window + 1}") for task in SIMULATED_PLANS for window in range(windows)]
    if sessions_per_cell < 1:
        raise ValueError("sessions_per_cell must be positive")
    if windows < 2:
        raise ValueError("windows must be at least 2 so a temporal holdout exists")
    if participants < len(cells):
        raise ValueError(f"participants must be at least {len(cells)}, one per task and window")
    generator = random.Random(seed)
    people: dict[tuple[str, str], list[_Person]] = {cell: [] for cell in cells}
    for number in range(participants):
        people[cells[number % len(cells)]].append(
            _Person(
                code=f"p{number + 1:02d}",
                pace=math.exp(generator.gauss(0.0, _PERSONAL_PACE_SPREAD)),
                irregularity=generator.uniform(0.25, 0.55),
            )
        )

    records: list[dict[str, Any]] = []
    labels: dict[str, bool] = {}
    tasks: dict[str, str] = {}
    window_by_session: dict[str, str] = {}
    groups: dict[str, str] = {}
    index = 0
    for (task, window), cell_people in people.items():
        for low, high in PACING_REGIMES.values():
            for automated in (True, False):
                for repeat in range(sessions_per_cell):
                    index += 1
                    session = "hmac-sha256:" + f"{index:064x}"
                    person = None if automated else cell_people[repeat % len(cell_people)]
                    pauses = [
                        _pause(generator, human_model, person, low, high)
                        for _ in SIMULATED_PLANS[task][1:]
                    ]
                    records.extend(_session_records(session, SIMULATED_PLANS[task], pauses))
                    labels[session] = automated
                    tasks[session] = task
                    window_by_session[session] = window
                    groups[session] = session if person is None else person.code
    return SimulatedCorpus(tuple(records), labels, tasks, window_by_session, groups)


def _session_records(
    session: str, plan: Sequence[str], pauses: Sequence[float]
) -> list[dict[str, Any]]:
    # Sessions start an hour apart so that no two overlap.
    moment = _EPOCH + timedelta(hours=int(session[-8:], 16))
    records = []
    for step, path in enumerate(plan):
        if step:
            moment += timedelta(seconds=pauses[step - 1])
        records.append(
            {
                "session_id": session,
                "request_uri": path,
                "request_method": "GET",
                "status": 200,
                "time_iso8601": moment.isoformat(),
            }
        )
    return records


def _pause(
    generator: random.Random,
    human_model: HumanPauseModel,
    person: _Person | None,
    low: float,
    high: float,
) -> float:
    if person is None or human_model is HumanPauseModel.UNIFORM:
        return generator.uniform(low, high)
    if human_model is HumanPauseModel.LINGER:
        if generator.random() < _LINGER_PROBABILITY:
            return person.pace * generator.uniform(high, 2 * high)
        return person.pace * generator.uniform(low, high)
    middle = person.pace * (low + high) / 2
    return math.exp(generator.gauss(math.log(middle), person.irregularity))


def plan_collection(
    *,
    human_model: HumanPauseModel,
    sessions_per_cell_options: Sequence[int],
    participants: int,
    repeats: int = 20,
    resamples: int = 300,
    seed: int = 0,
) -> dict[str, Any]:
    """Estimate how often the ladder detects `human_model` at each corpus size.

    For each size, `repeats` independent corpora run through the real preflight and
    baseline with participant-grouped splits. A detection is a final temporal holdout on
    which the logistic rung beats the constant baseline, by its session-cluster lower bound.
    """

    if repeats < 1:
        raise ValueError("repeats must be positive")
    rows = []
    for sessions_per_cell in sessions_per_cell_options:
        outcomes = [
            _final_temporal_outcome(
                simulate_matched_corpus(
                    human_model=human_model,
                    sessions_per_cell=sessions_per_cell,
                    participants=participants,
                    seed=seed * 1_000_003 + repeat,
                ),
                resamples=resamples,
                seed=repeat,
            )
            for repeat in range(repeats)
        ]
        scored = [outcome for outcome in outcomes if outcome is not None]
        rows.append(
            {
                "sessions_per_cell": sessions_per_cell,
                "sessions": sessions_per_cell
                * len(SIMULATED_PLANS)
                * SIMULATED_WINDOWS
                * len(PACING_REGIMES)
                * 2,
                "detection_rate": sum(beats for beats, _ in scored) / repeats,
                "mean_pr_auc": (
                    sum(pr_auc for _, pr_auc in scored) / len(scored) if scored else None
                ),
                "blocked_runs": repeats - len(scored),
            }
        )
    return {
        "fixture": True,
        "human_model": human_model.value,
        "participants": participants,
        "repeats": repeats,
        "resamples": resamples,
        "seed": seed,
        "sizes": rows,
    }


def _final_temporal_outcome(
    corpus: SimulatedCorpus, *, resamples: int, seed: int
) -> tuple[bool, float] | None:
    prepared = prepare_pf2_dataset(
        corpus.records,
        labels_by_session=corpus.labels,
        task_by_session=corpus.tasks,
        collection_window_by_session=corpus.windows,
        group_by_session=corpus.groups,
        min_sessions_per_task_class=1,
    )
    report = evaluate_pf2_baseline(
        prepared.model_rows, prepared.split_rows, resamples=resamples, seed=seed
    ).report
    final = next(
        (split for split in report["splits"] if split["final_temporal_holdout"]), None
    )
    if final is None or final["status"] != "evaluated":
        return None
    logistic = final["models"]["l2_logistic_regression"]
    return bool(final["logistic_beats_constant"]), float(logistic["pr_auc"])
