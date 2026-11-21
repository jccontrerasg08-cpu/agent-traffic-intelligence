from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime
from itertools import pairwise
from typing import Any

import pytest

from agent_traffic_intelligence.cli import main
from agent_traffic_intelligence.evaluation.pf2.protocol import (
    PF2_READING_LOAD,
    PF2_ROUTE_CATEGORIES,
    prepare_pf2_dataset,
)
from agent_traffic_intelligence.evaluation.pf2.simulation import (
    PACING_REGIMES,
    SIMULATED_PLANS,
    AutomationPauseModel,
    HumanPauseModel,
    SimulatedCorpus,
    SimulatedScenario,
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


# Captured on the code before imitation existed (specs/001-adversarial-timing, T001), so
# the plain timer must keep reproducing every corpus and every recorded result exactly.
_CHARACTERIZATION_DIGESTS = {
    HumanPauseModel.LINGER: "3a9a269d0a8c8f9cd76c2ab972171a89d7efd9008f2e2c6119b66d768279d937",
    HumanPauseModel.LOGNORMAL: "341bebf92d975b0bafd30f88e72ceb92575c97b6e902cb7890e4ff2d827b9b47",
}


def _digest(corpus: SimulatedCorpus) -> str:
    payload = json.dumps(
        [corpus.records, corpus.labels, corpus.tasks, corpus.windows, corpus.groups],
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@pytest.mark.parametrize("human_model", sorted(_CHARACTERIZATION_DIGESTS))
def test_the_plain_timer_reproduces_every_corpus_from_before_imitation(
    human_model: HumanPauseModel,
) -> None:
    corpus = simulate_matched_corpus(
        human_model=human_model, sessions_per_cell=2, participants=12, seed=7
    )

    assert _digest(corpus) == _CHARACTERIZATION_DIGESTS[human_model]


def _pauses_by_session(corpus: SimulatedCorpus) -> dict[str, list[float]]:
    stamps: dict[str, list[datetime]] = defaultdict(list)
    for record in corpus.records:
        stamps[record["session_id"]].append(datetime.fromisoformat(record["time_iso8601"]))
    return {
        session: [(later - earlier).total_seconds() for earlier, later in pairwise(times)]
        for session, times in stamps.items()
    }


def _imitating(
    fidelity: float, human_model: HumanPauseModel = HumanPauseModel.LINGER
) -> SimulatedCorpus:
    return simulate_matched_corpus(
        human_model=human_model,
        sessions_per_cell=2,
        participants=12,
        seed=7,
        automation_model=AutomationPauseModel.IMITATE,
        imitation_fidelity=fidelity,
    )


def test_imitation_at_fidelity_zero_is_the_plain_timer() -> None:
    assert _digest(_imitating(0.0)) == _CHARACTERIZATION_DIGESTS[HumanPauseModel.LINGER]


def test_full_imitation_makes_automated_pauses_person_like() -> None:
    corpus = _imitating(1.0)
    timer_high = max(bounds[1] for bounds in PACING_REGIMES.values())

    automated = [
        pause
        for session, pauses in _pauses_by_session(corpus).items()
        if corpus.labels[session]
        for pause in pauses
    ]
    # A lingering person runs past the range; the timer never does.
    assert max(automated) > timer_high


def test_imitation_leaves_every_human_session_unchanged() -> None:
    timer = _pauses_by_session(_imitating(0.0))
    imitated = _imitating(0.75)

    for session, pauses in _pauses_by_session(imitated).items():
        if not imitated.labels[session]:
            assert pauses == timer[session]
    assert imitated.groups == _imitating(0.0).groups


def test_an_imitating_session_never_takes_a_participant_code() -> None:
    corpus = _imitating(1.0)

    participants = {corpus.groups[s] for s, automated in corpus.labels.items() if not automated}
    automated_groups = {corpus.groups[s] for s, automated in corpus.labels.items() if automated}
    assert not participants & automated_groups


@pytest.mark.parametrize(
    ("automation_model", "fidelity", "message"),
    [
        (AutomationPauseModel.IMITATE, -0.1, "between 0 and 1"),
        (AutomationPauseModel.IMITATE, 1.5, "between 0 and 1"),
        (AutomationPauseModel.TIMER, 0.5, "needs the imitate"),
    ],
)
def test_inconsistent_imitation_is_refused(
    automation_model: AutomationPauseModel, fidelity: float, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        simulate_matched_corpus(
            human_model=HumanPauseModel.LINGER,
            sessions_per_cell=1,
            participants=6,
            automation_model=automation_model,
            imitation_fidelity=fidelity,
        )
    with pytest.raises(ValueError, match=message):
        plan_collection(
            human_model=HumanPauseModel.LINGER,
            sessions_per_cell_options=[1],
            participants=6,
            automation_model=automation_model,
            imitation_fidelity=fidelity,
        )


def test_a_perfect_mimic_removes_what_the_timer_lets_the_ladder_detect() -> None:
    # Paired: both plans score the same human sessions; only the automation differs.
    def plan(fidelity: float) -> dict[str, Any]:
        return plan_collection(
            human_model=HumanPauseModel.LOGNORMAL,
            sessions_per_cell_options=[2],
            participants=12,
            repeats=5,
            resamples=200,
            automation_model=AutomationPauseModel.IMITATE,
            imitation_fidelity=fidelity,
        )

    timer, mimic = plan(0.0), plan(1.0)

    assert mimic["automation_model"] == "imitate"
    assert mimic["imitation_fidelity"] == 1.0
    assert timer["sizes"][0]["detection_rate"] >= 0.8
    # One chance detection in five is allowed: a null is not detected more often.
    assert mimic["sizes"][0]["detection_rate"] <= 0.2


def test_cli_records_the_imitating_adversary_in_the_plan(tmp_path, capsys) -> None:
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
            "1",
            "--resamples",
            "20",
            "--automation-model",
            "imitate",
            "--imitation-fidelity",
            "0.5",
            "--output",
            str(output),
        ]
    )

    assert code == 0
    capsys.readouterr()
    plan = json.loads(output.read_text())
    assert (plan["automation_model"], plan["imitation_fidelity"]) == ("imitate", 0.5)


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--automation-model", "imitate", "--imitation-fidelity", "1.5"], "between 0 and 1"),
        (["--imitation-fidelity", "0.5"], "needs the imitate"),
    ],
)
def test_cli_refuses_inconsistent_imitation_and_writes_nothing(
    tmp_path, capsys, extra: list[str], message: str
) -> None:
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
            "--output",
            str(output),
            *extra,
        ]
    )

    assert code == 2
    assert message in capsys.readouterr().err
    assert not output.exists()


def test_imitating_a_timer_like_person_still_runs_and_reports() -> None:
    plan = plan_collection(
        human_model=HumanPauseModel.UNIFORM,
        sessions_per_cell_options=[1],
        participants=6,
        repeats=1,
        resamples=20,
        automation_model=AutomationPauseModel.IMITATE,
        imitation_fidelity=1.0,
    )

    assert plan["human_model"] == "uniform"
    assert plan["automation_model"] == "imitate"
    assert len(plan["sizes"]) == 1


def _reading(
    automation_model: AutomationPauseModel = AutomationPauseModel.TIMER, fidelity: float = 0.0
) -> SimulatedCorpus:
    return simulate_matched_corpus(
        human_model=HumanPauseModel.LOGNORMAL,
        sessions_per_cell=2,
        participants=12,
        seed=7,
        automation_model=automation_model,
        imitation_fidelity=fidelity,
        scenario=SimulatedScenario.READING,
    )


def _dwell_ratio(corpus: SimulatedCorpus, session: str) -> float:
    navigations = [
        (record["request_uri"], datetime.fromisoformat(record["time_iso8601"]))
        for record in corpus.records
        if record["session_id"] == session and "/assets/" not in record["request_uri"]
    ]
    dwell: dict[str, list[float]] = defaultdict(list)
    for (path, started), (_, left) in pairwise(navigations):
        load = PF2_READING_LOAD[PF2_ROUTE_CATEGORIES[path]]
        dwell[load].append((left - started).total_seconds())
    return (sum(dwell["long"]) / len(dwell["long"])) / (sum(dwell["short"]) / len(dwell["short"]))


def _mean_ratio(corpus: SimulatedCorpus, automated: bool) -> float:
    ratios = [_dwell_ratio(corpus, s) for s, label in corpus.labels.items() if label == automated]
    return sum(ratios) / len(ratios)


def test_in_the_reading_scenario_assets_follow_their_page_for_both_cohorts() -> None:
    corpus = _reading()

    for session, pauses in _pauses_by_session(corpus).items():
        plan = SIMULATED_PLANS[corpus.tasks[session]]
        asset_pauses = [p for p, path in zip(pauses, plan[1:], strict=True) if "/assets/" in path]
        assert asset_pauses and all(pause < 1.0 for pause in asset_pauses)


def test_people_dwell_longer_on_long_pages_and_the_timer_does_not() -> None:
    corpus = _reading()

    assert _mean_ratio(corpus, automated=False) > 1.6
    assert _mean_ratio(corpus, automated=True) < 1.3


def test_the_null_ignores_the_content_in_the_reading_scenario() -> None:
    corpus = simulate_matched_corpus(
        human_model=HumanPauseModel.UNIFORM,
        sessions_per_cell=2,
        participants=12,
        seed=7,
        scenario=SimulatedScenario.READING,
    )

    assert _mean_ratio(corpus, automated=False) < 1.3
    assert _mean_ratio(corpus, automated=True) < 1.3


def test_the_null_is_not_detected_in_the_reading_scenario() -> None:
    null = plan_collection(
        human_model=HumanPauseModel.UNIFORM,
        sessions_per_cell_options=[2],
        participants=12,
        repeats=5,
        resamples=200,
        scenario=SimulatedScenario.READING,
    )

    # One chance detection in five is allowed, as for the content-aware mimic.
    assert null["sizes"][0]["detection_rate"] <= 0.2


def test_only_the_content_aware_mimic_places_its_dwell_by_content() -> None:
    blind = _reading(AutomationPauseModel.IMITATE, 1.0)
    aware = _reading(AutomationPauseModel.IMITATE_CONTENT, 1.0)

    assert _mean_ratio(aware, automated=True) > 1.6
    assert _mean_ratio(blind, automated=True) < 1.4


def test_reading_human_sessions_are_the_same_whichever_automation_runs() -> None:
    timer = _pauses_by_session(_reading())
    aware = _reading(AutomationPauseModel.IMITATE_CONTENT, 1.0)

    for session, pauses in _pauses_by_session(aware).items():
        if not aware.labels[session]:
            assert pauses == timer[session]


def test_the_content_aware_mimic_needs_the_reading_scenario() -> None:
    with pytest.raises(ValueError, match="needs the reading scenario"):
        simulate_matched_corpus(
            human_model=HumanPauseModel.LOGNORMAL,
            sessions_per_cell=1,
            participants=6,
            automation_model=AutomationPauseModel.IMITATE_CONTENT,
            imitation_fidelity=1.0,
        )


def test_dwell_ratio_detects_the_distribution_mimic_and_not_the_content_aware_one() -> None:
    # Paired: both plans score the same human sessions; only the adversary differs.
    def plan(model: AutomationPauseModel) -> dict[str, Any]:
        return plan_collection(
            human_model=HumanPauseModel.LOGNORMAL,
            sessions_per_cell_options=[2],
            participants=12,
            repeats=5,
            resamples=200,
            automation_model=model,
            imitation_fidelity=1.0,
            scenario=SimulatedScenario.READING,
        )

    blind, aware = plan(AutomationPauseModel.IMITATE), plan(AutomationPauseModel.IMITATE_CONTENT)

    assert blind["scenario"] == "reading"
    assert blind["sizes"][0]["detection_rate"] >= 0.8
    # One chance detection in five is allowed: the content-aware mimic is a null here.
    assert aware["sizes"][0]["detection_rate"] <= 0.2


def test_cli_runs_the_reading_scenario_against_the_content_aware_mimic(tmp_path, capsys) -> None:
    output = tmp_path / "plan.json"

    code = main(
        [
            "pf2-simulate",
            "--scenario",
            "reading",
            "--human-model",
            "lognormal",
            "--sessions-per-cell",
            "1",
            "--participants",
            "6",
            "--repeats",
            "1",
            "--resamples",
            "20",
            "--automation-model",
            "imitate-content",
            "--imitation-fidelity",
            "1",
            "--output",
            str(output),
        ]
    )

    assert code == 0
    capsys.readouterr()
    plan = json.loads(output.read_text())
    assert (plan["scenario"], plan["automation_model"]) == ("reading", "imitate-content")


def test_cli_refuses_the_content_aware_mimic_without_reading(tmp_path, capsys) -> None:
    code = main(
        [
            "pf2-simulate",
            "--human-model",
            "lognormal",
            "--sessions-per-cell",
            "1",
            "--participants",
            "6",
            "--automation-model",
            "imitate-content",
            "--imitation-fidelity",
            "1",
            "--output",
            str(tmp_path / "plan.json"),
        ]
    )

    assert code == 2
    assert "needs the reading scenario" in capsys.readouterr().err
