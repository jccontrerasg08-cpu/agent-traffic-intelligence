from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest


def _session(value: str) -> str:
    return "hmac-sha256:" + value * 64


def _record(
    session_id: str,
    path: str,
    offset_seconds: int,
    *,
    method: str = "GET",
    status: int = 200,
) -> dict[str, object]:
    return {
        "session_id": session_id,
        "request_uri": path,
        "request_method": method,
        "status": status,
        "time_iso8601": (
            datetime(2026, 8, 25, tzinfo=UTC) + timedelta(seconds=offset_seconds)
        ).isoformat(),
    }


def test_pf2_preflight_materializes_fixed_width_features_without_audit_identifiers() -> None:
    from agent_traffic_intelligence.pf2_protocol import prepare_pf2_dataset

    automated = _session("a")
    human = _session("b")
    records = [
        _record(automated, "/lab/start", 0),
        _record(automated, "/lab/page/landing", 1),
        _record(automated, "/lab/page/catalog", 3),
        _record(automated, "/lab/page/related", 8),
        _record(automated, "/lab/complete", 14),
        _record(human, "/lab/start", 0),
        _record(human, "/lab/page/landing", 2),
        _record(human, "/lab/page/catalog", 6),
        _record(human, "/lab/page/detail", 15),
        _record(human, "/lab/complete", 28),
    ]

    dataset = prepare_pf2_dataset(
        records,
        labels_by_session={automated: True, human: False},
        task_by_session={automated: "task-a", human: "task-a"},
        min_sessions_per_task_class=1,
    )

    assert dataset.preflight["status"] == "blocked-no-task-holdout"
    assert dataset.preflight["session_count"] == 2
    assert dataset.preflight["varying_feature_count"] > 0
    assert len(dataset.model_rows) == 2
    assert {row["automated"] for row in dataset.model_rows} == {False, True}
    assert dataset.split_rows == (
        {"row_index": 0, "session_id": automated, "task": "task-a"},
        {"row_index": 1, "session_id": human, "task": "task-a"},
    )
    for row in dataset.model_rows:
        assert "session_id" not in row
        assert "task" not in row
        assert "time_iso8601" not in row
        assert "request_id" not in row
        assert "ua_provenance_bucket" not in row
        assert "route_related_count" in row
        assert "route_detail_count" in row
        assert "delay_bin_1_to_4_count" in row


def test_pf2_preflight_rejects_task_without_both_classes() -> None:
    from agent_traffic_intelligence.pf2_protocol import PF2ProtocolError, prepare_pf2_dataset

    automated = _session("c")
    records = [
        _record(automated, "/lab/start", 0),
        _record(automated, "/lab/page/landing", 2),
        _record(automated, "/lab/complete", 7),
    ]

    with pytest.raises(PF2ProtocolError, match="both classes"):
        prepare_pf2_dataset(
            records,
            labels_by_session={automated: True},
            task_by_session={automated: "task-a"},
            min_sessions_per_task_class=1,
        )


def test_pf2_preflight_rejects_unknown_route_and_does_not_treat_it_as_feature() -> None:
    from agent_traffic_intelligence.pf2_protocol import PF2ProtocolError, prepare_pf2_dataset

    automated = _session("d")
    human = _session("e")
    records = [
        _record(automated, "/lab/start", 0),
        _record(automated, "/lab/not-approved", 1),
        _record(human, "/lab/start", 0),
        _record(human, "/lab/complete", 2),
    ]

    with pytest.raises(PF2ProtocolError, match="eligible ATI-PF-2 route"):
        prepare_pf2_dataset(
            records,
            labels_by_session={automated: True, human: False},
            task_by_session={automated: "task-a", human: "task-a"},
            min_sessions_per_task_class=1,
        )


def test_pf2_preflight_cli_writes_model_and_split_artifacts_separately(
    tmp_path, capsys
) -> None:
    from agent_traffic_intelligence import cli

    automated = _session("f")
    human = _session("0")
    records = [
        _record(automated, "/lab/start", 0),
        _record(automated, "/lab/page/related", 2),
        _record(automated, "/lab/complete", 8),
        _record(human, "/lab/start", 0),
        _record(human, "/lab/page/detail", 7),
        _record(human, "/lab/complete", 21),
    ]
    records_path = tmp_path / "records.jsonl"
    labels_path = tmp_path / "labels.json"
    tasks_path = tmp_path / "tasks.json"
    model_path = tmp_path / "model.jsonl"
    split_path = tmp_path / "split.jsonl"
    preflight_path = tmp_path / "preflight.json"
    records_path.write_text(
        "".join(__import__("json").dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    labels_path.write_text(
        __import__("json").dumps({automated: True, human: False}), encoding="utf-8"
    )
    tasks_path.write_text(
        __import__("json").dumps({automated: "task-a", human: "task-a"}), encoding="utf-8"
    )

    assert (
        cli.main(
            [
                "pf2-preflight",
                str(records_path),
                "--labels-by-session",
                str(labels_path),
                "--tasks-by-session",
                str(tasks_path),
                "--model-output",
                str(model_path),
                "--split-output",
                str(split_path),
                "--preflight-output",
                str(preflight_path),
                "--min-sessions-per-task-class",
                "1",
            ]
        )
        == 0
    )

    model_serialized = model_path.read_text(encoding="utf-8")
    preflight_serialized = preflight_path.read_text(encoding="utf-8")
    split_serialized = split_path.read_text(encoding="utf-8")
    assert '"session_id"' not in model_serialized
    assert automated not in model_serialized
    assert human not in model_serialized
    assert automated not in preflight_serialized
    assert human not in preflight_serialized
    assert automated in split_serialized
    assert human in split_serialized
    assert '"status": "blocked-no-task-holdout"' in preflight_serialized
    assert automated not in capsys.readouterr().out


def test_pf2_preflight_rejects_integrity_only_missing_route() -> None:
    from agent_traffic_intelligence.pf2_protocol import PF2ProtocolError, prepare_pf2_dataset

    automated = _session("1")
    human = _session("2")
    records = [
        _record(automated, "/lab/start", 0),
        _record(automated, "/lab/missing", 2, status=404),
        _record(human, "/lab/start", 0),
        _record(human, "/lab/complete", 2),
    ]

    with pytest.raises(PF2ProtocolError, match="eligible ATI-PF-2 route"):
        prepare_pf2_dataset(
            records,
            labels_by_session={automated: True, human: False},
            task_by_session={automated: "task-a", human: "task-a"},
            min_sessions_per_task_class=1,
        )


def test_pf2_preflight_blocks_baseline_without_a_task_holdout() -> None:
    from agent_traffic_intelligence.pf2_protocol import prepare_pf2_dataset

    automated = _session("3")
    human = _session("4")
    records = [
        _record(automated, "/lab/start", 0),
        _record(automated, "/lab/page/related", 3),
        _record(automated, "/lab/complete", 8),
        _record(human, "/lab/start", 0),
        _record(human, "/lab/page/detail", 6),
        _record(human, "/lab/complete", 18),
    ]

    dataset = prepare_pf2_dataset(
        records,
        labels_by_session={automated: True, human: False},
        task_by_session={automated: "task-a", human: "task-a"},
        min_sessions_per_task_class=1,
    )

    assert dataset.preflight["status"] == "blocked-no-task-holdout"
