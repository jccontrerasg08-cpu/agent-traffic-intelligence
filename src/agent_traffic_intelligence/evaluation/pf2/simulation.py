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
from agent_traffic_intelligence.evaluation.pf2.protocol import (
    PF2_READING_LOAD,
    PF2_ROUTE_CATEGORIES,
    prepare_pf2_dataset,
)

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
# How much a page's reading load stretches a reader's pause before the next navigation.
_LOAD_FACTOR = MappingProxyType({"short": 0.8, "long": 1.6})
# The overreading adversary's factors: a long-over-short ratio about 1.6 times a person's,
# as the advanced bots' median ratio is to the people's in Iliou et al.'s phase 1.
_OVERREAD_LOAD_FACTOR = MappingProxyType({"short": 0.6, "long": 1.9})
_CONTENT_AWARE = frozenset({"imitate-content", "overread"})
_ASSET_DELAY = (0.05, 0.4)
_PERSONAL_PACE_SPREAD = 0.25
_LINGER_PROBABILITY = 0.3


class HumanPauseModel(StrEnum):
    """How a simulated person chooses each pause when shown a regime's range."""

    UNIFORM = "uniform"
    """Indistinguishable from the timer, in the reading scenario too, where it ignores the
    content as the timer does. The ladder must not claim a win against it."""

    LINGER = "linger"
    """Like the timer, except that some pauses run past the range."""

    LOGNORMAL = "lognormal"
    """Aims at the middle of the range with a personal, right-skewed irregularity."""


class AutomationPauseModel(StrEnum):
    """How simulated automation chooses each pause."""

    TIMER = "timer"
    """Draws every pause uniformly within the regime, like the laboratory executor."""

    IMITATE = "imitate"
    """Replaces each timer pause, with probability equal to the imitation fidelity, by a
    pause drawn the way the human model draws one, with traits of its own. In the reading
    scenario it copies how long people dwell but not where: it scales its pauses by the
    session's reading loads in a random order."""

    IMITATE_CONTENT = "imitate-content"
    """Like `imitate`, but in the reading scenario it also dwells longer on long pages, as
    people do. Only meaningful in the reading scenario."""

    OVERREAD = "overread"
    """Like `imitate-content`, but it overdoes it: long pages stretch its pauses much more,
    and short pages shrink them more, than they do a person's. The advanced bots of Iliou
    et al.'s public dataset dwell this way. Only meaningful in the reading scenario. It
    exists in simulation only: the laboratory executor has no overreading mode, so plan
    real collections with the adversaries it can run."""


class SimulatedScenario(StrEnum):
    """Which laboratory scenario the corpus simulates."""

    KEYPRESS = "keypress"
    """Scenario ati-pf2-1.0: every step, assets included, waits for a pause."""

    READING = "reading"
    """Scenario ati-pf2-1.1: assets follow their page at once, and a person stays on a page
    for longer the more it gives them to read."""


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
    automation_model: AutomationPauseModel = AutomationPauseModel.TIMER,
    imitation_fidelity: float = 0.0,
    scenario: SimulatedScenario = SimulatedScenario.KEYPRESS,
) -> SimulatedCorpus:
    """Build one corpus with `sessions_per_cell` sessions per task, window, regime and cohort.

    Participants are spread over the task-by-window cells, so there must be at least one
    per cell. A cell's consented sessions rotate among that cell's participants.

    Imitation draws only from its own random stream, seeded from `seed`. The main stream
    therefore produces the same participants, human pauses and timer pauses at every
    fidelity, and fidelity 0 reproduces the plain timer exactly. The reading scenario draws
    its asset delays from a third stream, so its human sessions are the same whichever
    automation runs against them.
    """

    _validated_imitation(automation_model, imitation_fidelity, scenario)

    cells = [(task, f"w{window + 1}") for task in SIMULATED_PLANS for window in range(windows)]
    if sessions_per_cell < 1:
        raise ValueError("sessions_per_cell must be positive")
    if windows < 2:
        raise ValueError("windows must be at least 2 so a temporal holdout exists")
    if participants < len(cells):
        raise ValueError(f"participants must be at least {len(cells)}, one per task and window")
    generator = random.Random(seed)
    imitation = random.Random(f"imitation-{seed}")
    reading = random.Random(f"reading-{seed}")
    imitating = automation_model is not AutomationPauseModel.TIMER
    people: dict[tuple[str, str], list[_Person]] = {cell: [] for cell in cells}
    for number in range(participants):
        people[cells[number % len(cells)]].append(_draw_person(generator, f"p{number + 1:02d}"))

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
                    plan = SIMULATED_PLANS[task]
                    pauses = [
                        _pause(generator, human_model, person, low, high) for _ in plan[1:]
                    ]
                    imitated = [False] * len(pauses)
                    if automated and imitating:
                        pauses, imitated = _imitate(
                            pauses, imitation, human_model, imitation_fidelity, low, high
                        )
                    if scenario is SimulatedScenario.READING:
                        pauses = _read(
                            plan,
                            pauses,
                            reading,
                            imitation,
                            follows_content=_follows_content(
                                automated, imitated, automation_model, human_model
                            ),
                            load_factor=(
                                _OVERREAD_LOAD_FACTOR
                                if automated
                                and automation_model is AutomationPauseModel.OVERREAD
                                else _LOAD_FACTOR
                            ),
                        )
                    records.extend(_session_records(session, plan, pauses))
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


def _validated_imitation(
    automation_model: AutomationPauseModel, fidelity: float, scenario: SimulatedScenario
) -> None:
    if not 0.0 <= fidelity <= 1.0:
        raise ValueError("imitation_fidelity must be between 0 and 1")
    if automation_model is AutomationPauseModel.TIMER and fidelity != 0.0:
        raise ValueError("imitation_fidelity needs the imitate automation model")
    if (
        automation_model.value in _CONTENT_AWARE
        and scenario is not SimulatedScenario.READING
    ):
        raise ValueError(f"{automation_model.value} needs the reading scenario")


def _follows_content(
    automated: bool,
    imitated: list[bool],
    automation_model: AutomationPauseModel,
    human_model: HumanPauseModel,
) -> list[bool | None]:
    """Say, per pause, whether its length follows the page: yes, no, or shuffled (None).

    People follow the content, except under the null, whose people are indistinguishable
    from the timer in every respect. A timer pause does not follow it. An imitated pause
    follows it only for the content-aware mimic; the distribution mimic scales it by a
    misplaced load.
    """

    if human_model is HumanPauseModel.UNIFORM:
        # Under the null nobody follows the content, so an imitation of it does not either.
        return [False] * len(imitated)
    if not automated:
        return [True] * len(imitated)
    content_aware = automation_model.value in _CONTENT_AWARE
    return [(True if content_aware else None) if copied else False for copied in imitated]


def _read(
    plan: Sequence[str],
    pauses: list[float],
    reading: random.Random,
    imitation: random.Random,
    *,
    follows_content: list[bool | None],
    load_factor: Mapping[str, float] = _LOAD_FACTOR,
) -> list[float]:
    """Turn keypress pauses into the reading scenario's timing.

    An asset follows its page after a short fetch delay. A navigation's pause is scaled by
    `load_factor` at the reading load of the page being left: its own load when the pause
    follows content, a shuffled one of the session's loads when it is a distribution
    mimic's, none for a
    timer.
    """

    loads: list[str] = []
    page = plan[0]
    for path in plan[1:]:
        if PF2_ROUTE_CATEGORIES[path] != "asset":
            loads.append(PF2_READING_LOAD[PF2_ROUTE_CATEGORIES[page]])
            page = path
    misplaced = list(loads)
    if None in follows_content:
        imitation.shuffle(misplaced)
    result = []
    navigation = 0
    for path, pause, follows in zip(plan[1:], pauses, follows_content, strict=True):
        if PF2_ROUTE_CATEGORIES[path] == "asset":
            result.append(reading.uniform(*_ASSET_DELAY))
            continue
        if follows is True:
            pause *= load_factor[loads[navigation]]
        elif follows is None:
            pause *= load_factor[misplaced[navigation]]
        result.append(pause)
        navigation += 1
    return result


def _draw_person(generator: random.Random, code: str) -> _Person:
    """Draw the traits of one simulated person, participant or imitating persona alike."""

    return _Person(
        code=code,
        pace=math.exp(generator.gauss(0.0, _PERSONAL_PACE_SPREAD)),
        irregularity=generator.uniform(0.25, 0.55),
    )


def _imitate(
    timer_pauses: list[float],
    imitation: random.Random,
    human_model: HumanPauseModel,
    fidelity: float,
    low: float,
    high: float,
) -> tuple[list[float], list[bool]]:
    """Replace some timer pauses with person-like ones from a persona of the session's own.

    The persona is never a participant: sharing one would tie an automated session to a
    person, which the participant-grouped splits cannot purge.
    """

    persona = _draw_person(imitation, "persona")
    pauses: list[float] = []
    imitated: list[bool] = []
    for pause in timer_pauses:
        copied = imitation.random() < fidelity
        pauses.append(_pause(imitation, human_model, persona, low, high) if copied else pause)
        imitated.append(copied)
    return pauses, imitated


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
    automation_model: AutomationPauseModel = AutomationPauseModel.TIMER,
    imitation_fidelity: float = 0.0,
    scenario: SimulatedScenario = SimulatedScenario.KEYPRESS,
) -> dict[str, Any]:
    """Estimate how often the ladder detects `human_model` at each corpus size.

    For each size, `repeats` independent corpora run through the real preflight and
    baseline with participant-grouped splits. A detection is a final temporal holdout on
    which the logistic rung beats the constant baseline, by its session-cluster lower bound.
    """

    if repeats < 1:
        raise ValueError("repeats must be positive")
    _validated_imitation(automation_model, imitation_fidelity, scenario)
    rows = []
    for sessions_per_cell in sessions_per_cell_options:
        outcomes = [
            _final_temporal_outcome(
                simulate_matched_corpus(
                    human_model=human_model,
                    sessions_per_cell=sessions_per_cell,
                    participants=participants,
                    seed=seed * 1_000_003 + repeat,
                    automation_model=automation_model,
                    imitation_fidelity=imitation_fidelity,
                    scenario=scenario,
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
        "scenario": scenario.value,
        "human_model": human_model.value,
        "automation_model": automation_model.value,
        "imitation_fidelity": imitation_fidelity,
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
