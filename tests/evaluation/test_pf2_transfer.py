"""Transfer evaluation: what a model trained on one adversary does against another."""

from __future__ import annotations

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
    PF2_TARGET_NAME,
)
from agent_traffic_intelligence.evaluation.pf2.simulation import (
    AutomationPauseModel,
    HumanPauseModel,
    SimulatedScenario,
    simulate_matched_corpus,
)
from agent_traffic_intelligence.evaluation.pf2.transfer import (
    auc,
    human_reference,
    plan_transfer,
)


def _transfer(test: AutomationPauseModel, human: HumanPauseModel = HumanPauseModel.LOGNORMAL):
    return plan_transfer(
        human_model=human,
        sessions_per_cell=2,
        participants=12,
        train_automation_model=AutomationPauseModel.TIMER,
        test_automation_model=test,
        test_imitation_fidelity=0.0 if test is AutomationPauseModel.TIMER else 1.0,
        repeats=4,
    )["scores"]


def _mean_dwell_ratio(model: AutomationPauseModel, automated: bool) -> float:
    corpus = simulate_matched_corpus(
        human_model=HumanPauseModel.LOGNORMAL,
        sessions_per_cell=2,
        participants=12,
        seed=7,
        automation_model=model,
        imitation_fidelity=1.0,
        scenario=SimulatedScenario.READING,
    )
    sessions: dict[str, list[tuple[str, datetime]]] = defaultdict(list)
    for record in corpus.records:
        if corpus.labels[record["session_id"]] is automated:
            path = record["request_uri"]
            if PF2_ROUTE_CATEGORIES[path] != "asset":
                sessions[record["session_id"]].append(
                    (path, datetime.fromisoformat(record["time_iso8601"]))
                )
    ratios = []
    for navigations in sessions.values():
        dwell: dict[str, list[float]] = defaultdict(list)
        for (path, started), (_, left) in pairwise(navigations):
            load = PF2_READING_LOAD[PF2_ROUTE_CATEGORIES[path]]
            dwell[load].append((left - started).total_seconds())
        ratios.append(
            (sum(dwell["long"]) / len(dwell["long"])) / (sum(dwell["short"]) / len(dwell["short"]))
        )
    return sum(ratios) / len(ratios)


def test_auc_counts_ties_as_half_and_needs_both_classes() -> None:
    assert auc([0.9, 0.1], [True, False]) == 1.0
    assert auc([0.5, 0.5], [True, False]) == 0.5
    with pytest.raises(ValueError):
        auc([0.5], [True])


def test_the_human_reference_flags_departures_in_either_direction() -> None:
    train = [{PF2_TARGET_NAME: False, "x": 2} for _ in range(8)]
    train += [{PF2_TARGET_NAME: False, "x": 1}, {PF2_TARGET_NAME: True, "x": 0}]
    score = human_reference(train, ["x"])

    assert score({"x": 2}) < score({"x": 1}) < score({"x": 0})
    assert score({"x": 0}) == score({"x": 3})


def test_the_human_reference_needs_people() -> None:
    with pytest.raises(ValueError, match="no people"):
        human_reference([{PF2_TARGET_NAME: True, "x": 1}], ["x"])


def test_the_overreading_adversary_dwells_beyond_people() -> None:
    people = _mean_dwell_ratio(AutomationPauseModel.OVERREAD, automated=False)
    overread = _mean_dwell_ratio(AutomationPauseModel.OVERREAD, automated=True)

    assert overread > 1.3 * people > 2.0


def test_overreading_needs_the_reading_scenario() -> None:
    with pytest.raises(ValueError, match="reading scenario"):
        simulate_matched_corpus(
            human_model=HumanPauseModel.LOGNORMAL,
            sessions_per_cell=1,
            participants=6,
            automation_model=AutomationPauseModel.OVERREAD,
            imitation_fidelity=1.0,
        )


def test_against_the_trained_adversary_the_logistic_rung_is_best() -> None:
    scores = _transfer(AutomationPauseModel.TIMER)

    assert scores["l2_logistic_regression"]["mean_auc"] > 0.85
    assert scores["human_reference"]["mean_auc"] > 0.7


def test_an_overreader_inverts_the_logistic_rung_but_not_the_human_reference() -> None:
    scores = _transfer(AutomationPauseModel.OVERREAD)

    assert scores["l2_logistic_regression"]["mean_auc"] < 0.4
    assert scores["l2_logistic_regression"]["inverted_rate"] == 1.0
    assert scores["human_reference"]["mean_auc"] > 0.55
    assert scores["combined"]["mean_auc"] > scores["l2_logistic_regression"]["mean_auc"]


def test_no_score_wins_against_the_null() -> None:
    scores = _transfer(AutomationPauseModel.OVERREAD, human=HumanPauseModel.UNIFORM)

    assert all(0.35 < entry["mean_auc"] < 0.65 for entry in scores.values())


def test_cli_writes_a_transfer_report_marked_as_a_fixture(tmp_path, capsys) -> None:
    output = tmp_path / "transfer.json"

    code = main(
        [
            "pf2-transfer", "--human-model", "lognormal", "--sessions-per-cell", "1",
            "--participants", "6", "--repeats", "2",
            "--train-automation-model", "timer",
            "--test-automation-model", "overread", "--test-imitation-fidelity", "1",
            "--output", str(output),
        ]
    )  # fmt: skip

    report: dict[str, Any] = json.loads(output.read_text())
    assert code == 0
    assert report["fixture"] is True
    assert report["test"]["automation_model"] == "overread"
    assert set(report["scores"]) == {"l2_logistic_regression", "human_reference", "combined"}
    assert json.loads(capsys.readouterr().out)["fixture"] is True


def test_cli_refuses_an_inconsistent_adversary_and_writes_nothing(tmp_path, capsys) -> None:
    output = tmp_path / "transfer.json"

    code = main(
        [
            "pf2-transfer", "--human-model", "lognormal", "--sessions-per-cell", "1",
            "--participants", "6", "--repeats", "1", "--scenario", "keypress",
            "--train-automation-model", "timer",
            "--test-automation-model", "overread", "--test-imitation-fidelity", "1",
            "--output", str(output),
        ]
    )  # fmt: skip

    assert code == 2
    assert not output.exists()
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"test_imitation_fidelity": 0.0}, "overread needs an imitation fidelity above 0"),
        ({"repeats": 500_000}, "repeats must be between 1 and 499999"),
        ({"repeats": 0}, "repeats must be between"),
    ],
)
def test_a_transfer_that_would_misreport_is_refused(
    options: dict[str, Any], message: str
) -> None:
    arguments: dict[str, Any] = {
        "human_model": HumanPauseModel.LOGNORMAL,
        "sessions_per_cell": 1,
        "participants": 6,
        "train_automation_model": AutomationPauseModel.TIMER,
        "test_automation_model": AutomationPauseModel.OVERREAD,
        "test_imitation_fidelity": 1.0,
        "repeats": 1,
    }
    arguments.update(options)

    with pytest.raises(ValueError, match=message):
        plan_transfer(**arguments)


def test_the_refusal_names_the_adversary_that_needs_reading() -> None:
    with pytest.raises(ValueError, match=r"^overread needs the reading scenario$"):
        simulate_matched_corpus(
            human_model=HumanPauseModel.LOGNORMAL,
            sessions_per_cell=1,
            participants=6,
            automation_model=AutomationPauseModel.OVERREAD,
            imitation_fidelity=1.0,
            scenario=SimulatedScenario.KEYPRESS,
        )
