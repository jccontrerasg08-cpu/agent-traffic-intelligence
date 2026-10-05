from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from itertools import pairwise

import pytest

from agent_traffic_intelligence.cli import main
from agent_traffic_intelligence.evaluation.pf2.protocol import (
    PF2_ROUTE_CATEGORIES,
    prepare_pf2_dataset,
)
from agent_traffic_intelligence.evaluation.pf2.simulation import (
    PACING_REGIMES,
    SIMULATED_PLANS,
    HumanPauseModel,
    plan_collection,
    simulate_matched_corpus,
)


def test_a_simulated_corpus_follows_the_matched_design() -> None:
    corpus = simulate_matched_corpus(
        human_model=HumanPauseModel.LOGNORMAL, sessions_per_cell=2, participants=6
    )

    # 2 tasks x 3 windows x 3 regimes x 2 cohorts x 2 sessions.
    assert len(corpus.labels) == 72
    assert sum(corpus.labels.values()) == 36
    cells: dict[tuple[str, str], set[bool]] = defaultdict(set)
    for session, automated in corpus.labels.items():
        cells[(corpus.tasks[session], corpus.windows[session])].add(automated)
    assert all(classes == {False, True} for classes in cells.values())
    assert {record["request_uri"] for record in corpus.records} <= set(PF2_ROUTE_CATEGORIES)


def test_each_participant_stays_in_one_task_and_window() -> None:
    corpus = simulate_matched_corpus(
        human_model=HumanPauseModel.LINGER, sessions_per_cell=3, participants=12
    )

    places: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for session, automated in corpus.labels.items():
        if not automated:
            places[corpus.groups[session]].add((corpus.tasks[session], corpus.windows[session]))
    assert len(places) == 12
    assert all(len(cells) == 1 for cells in places.values())
    automated_groups = [corpus.groups[s] for s, automated in corpus.labels.items() if automated]
    assert len(set(automated_groups)) == len(automated_groups)


def test_automated_pauses_stay_inside_their_regime() -> None:
    corpus = simulate_matched_corpus(
        human_model=HumanPauseModel.LOGNORMAL, sessions_per_cell=1, participants=6
    )
    low = min(bounds[0] for bounds in PACING_REGIMES.values())
    high = max(bounds[1] for bounds in PACING_REGIMES.values())

    by_session: dict[str, list[str]] = defaultdict(list)
    for record in corpus.records:
        by_session[record["session_id"]].append(record["time_iso8601"])
    for session, stamps in by_session.items():
        if not corpus.labels[session]:
            continue
        times = [datetime.fromisoformat(stamp) for stamp in stamps]
        pauses = [(b - a).total_seconds() for a, b in pairwise(times)]
        assert len(pauses) == len(next(iter(SIMULATED_PLANS.values()))) - 1
        assert all(low <= pause <= high for pause in pauses)


def test_a_simulated_corpus_passes_the_real_preflight_with_groups() -> None:
    corpus = simulate_matched_corpus(
        human_model=HumanPauseModel.UNIFORM, sessions_per_cell=1, participants=6
    )

    prepared = prepare_pf2_dataset(
        corpus.records,
        labels_by_session=corpus.labels,
        task_by_session=corpus.tasks,
        collection_window_by_session=corpus.windows,
        group_by_session=corpus.groups,
        min_sessions_per_task_class=1,
    )

    assert prepared.preflight["status"] == "ready-for-baseline"
    assert prepared.preflight["group_count"] == 18 + 6


def test_a_simulation_is_deterministic_for_one_seed() -> None:
    first = simulate_matched_corpus(
        human_model=HumanPauseModel.LOGNORMAL, sessions_per_cell=1, participants=6, seed=4
    )
    second = simulate_matched_corpus(
        human_model=HumanPauseModel.LOGNORMAL, sessions_per_cell=1, participants=6, seed=4
    )

    assert first == second


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"sessions_per_cell": 0, "participants": 6}, "sessions_per_cell"),
        ({"sessions_per_cell": 1, "participants": 5}, "at least 6"),
        ({"sessions_per_cell": 1, "participants": 6, "windows": 1}, "temporal holdout"),
    ],
)
def test_an_impossible_design_is_refused(options: dict[str, int], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        simulate_matched_corpus(human_model=HumanPauseModel.UNIFORM, **options)


def test_a_clear_difference_is_detected_and_the_null_is_not() -> None:
    detected = plan_collection(
        human_model=HumanPauseModel.LOGNORMAL,
        sessions_per_cell_options=[4],
        participants=12,
        repeats=3,
        resamples=100,
    )
    null = plan_collection(
        human_model=HumanPauseModel.UNIFORM,
        sessions_per_cell_options=[4],
        participants=12,
        repeats=3,
        resamples=100,
    )

    assert detected["fixture"] is True
    assert detected["sizes"][0]["sessions"] == 144
    assert detected["sizes"][0]["detection_rate"] == 1.0
    assert null["sizes"][0]["detection_rate"] == 0.0


def test_cli_writes_a_collection_plan_marked_as_a_fixture(tmp_path, capsys) -> None:
    output = tmp_path / "plan.json"

    code = main(
        [
            "pf2-simulate",
            "--human-model",
            "linger",
            "--sessions-per-cell",
            "1",
            "--participants",
            "6",
            "--repeats",
            "2",
            "--resamples",
            "20",
            "--output",
            str(output),
        ]
    )

    assert code == 0
    assert json.loads(capsys.readouterr().out) == {"output": str(output), "fixture": True}
    plan = json.loads(output.read_text())
    assert plan["fixture"] is True
    assert [row["sessions_per_cell"] for row in plan["sizes"]] == [1]


def test_cli_refuses_too_few_participants(tmp_path, capsys) -> None:
    code = main(
        [
            "pf2-simulate",
            "--human-model",
            "uniform",
            "--sessions-per-cell",
            "1",
            "--participants",
            "2",
            "--output",
            str(tmp_path / "plan.json"),
        ]
    )

    assert code == 2
    assert "at least 6" in capsys.readouterr().err
