from __future__ import annotations

import json
from pathlib import Path

from agent_traffic_intelligence.cli import main


def write_input(path: Path) -> None:
    rows = [
        {
            "time_iso8601": "2026-08-14T08:00:00+00:00",
            "remote_addr": "203.0.113.9",
            "request_method": "GET",
            "request_uri": "/docs?token=never-log-this",
            "status": 200,
            "body_bytes_sent": 100,
            "server_protocol": "HTTP/2",
            "http_user_agent": "Mozilla/5.0 compatible; GPTBot/1.0",
        },
        {
            "time_iso8601": "2026-08-14T08:00:05+00:00",
            "remote_addr": "203.0.113.10",
            "request_method": "GET",
            "request_uri": "/home?email=private@example.com",
            "status": 200,
            "body_bytes_sent": 200,
            "server_protocol": "HTTP/2",
            "http_user_agent": "Mozilla/5.0",
            "http_cookie": "session=do-not-log",
        },
    ]
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def test_analyze_emits_privacy_safe_jsonl_and_summary(tmp_path, monkeypatch, capsys) -> None:
    input_path = tmp_path / "access.jsonl"
    output_path = tmp_path / "detections.jsonl"
    write_input(input_path)
    monkeypatch.setenv("ATI_HASH_KEY", "test-secret-key")

    code = main(["analyze", str(input_path), "--output", str(output_path), "--source", "nginx"])

    assert code == 0
    lines = output_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["identity"]["agent"] == "GPTBot"
    assert first["automation_score"] > 0.8

    serialized = output_path.read_text(encoding="utf-8")
    assert "203.0.113" not in serialized
    assert "never-log-this" not in serialized
    assert "private@example.com" not in serialized
    assert "do-not-log" not in serialized

    captured = capsys.readouterr()
    assert "processed=2" in captured.err


def test_campaign_labels_emits_privacy_safe_ground_truth_for_matching_marker(
    tmp_path, monkeypatch, capsys
) -> None:
    input_path = tmp_path / "access.jsonl"
    labels_path = tmp_path / "labels.jsonl"
    rows = [
        {
            "time_iso8601": "2026-08-19T08:00:00+00:00",
            "remote_addr": "203.0.113.9",
            "request_method": "GET",
            "request_uri": "/owned-path?token=never-log-this",
            "status": 200,
            "body_bytes_sent": 100,
            "server_protocol": "HTTP/2",
            "http_user_agent": "ControlledAgent/1.0",
            "ati_campaign_id": "owned-shadow-2026-08",
            "http_authorization": "Bearer do-not-log",
            "http_cookie": "session=do-not-log",
        },
        {
            "time_iso8601": "2026-08-19T08:00:05+00:00",
            "remote_addr": "203.0.113.10",
            "request_method": "GET",
            "request_uri": "/other-path?email=private@example.com",
            "status": 200,
            "body_bytes_sent": 100,
            "server_protocol": "HTTP/2",
            "ati_campaign_id": "other-campaign",
        },
    ]
    input_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    monkeypatch.setenv("ATI_HASH_KEY", "test-secret-key")

    code = main(
        [
            "campaign",
            "labels",
            str(input_path),
            "--campaign-id",
            "owned-shadow-2026-08",
            "--corpus-id",
            "owned-shadow-2026-08",
            "--output",
            str(labels_path),
        ]
    )

    assert code == 0
    labels = [json.loads(line) for line in labels_path.read_text(encoding="utf-8").splitlines()]
    assert labels == [
        {
            "automated": True,
            "corpus_id": "owned-shadow-2026-08",
            "label_confidence": 1.0,
            "label_source": "controlled-campaign",
            "request_id": labels[0]["request_id"],
        }
    ]
    serialized = labels_path.read_text(encoding="utf-8")
    assert "203.0.113" not in serialized
    assert "never-log-this" not in serialized
    assert "private@example.com" not in serialized
    assert "do-not-log" not in serialized
    assert "generated_label_count=1" in capsys.readouterr().err


def test_analyze_fails_cleanly_without_hash_key_for_raw_ip(tmp_path, monkeypatch, capsys) -> None:
    input_path = tmp_path / "access.jsonl"
    write_input(input_path)
    monkeypatch.delenv("ATI_HASH_KEY", raising=False)

    code = main(["analyze", str(input_path)])

    assert code == 2
    assert "ATI_HASH_KEY" in capsys.readouterr().err


def test_analyze_replaces_same_input_output_only_after_success(
    tmp_path, monkeypatch, capsys
) -> None:
    path = tmp_path / "access.jsonl"
    write_input(path)
    monkeypatch.setenv("ATI_HASH_KEY", "test-secret-key")

    code = main(["analyze", str(path), "--output", str(path)])

    assert code == 0
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2
    assert "processed=2" in capsys.readouterr().err


def test_analyze_preserves_existing_output_when_parsing_fails(
    tmp_path, monkeypatch, capsys
) -> None:
    input_path = tmp_path / "access.jsonl"
    output_path = tmp_path / "detections.jsonl"
    input_path.write_text('{"not":"a complete event"}\n', encoding="utf-8")
    output_path.write_text("previous-successful-output\n", encoding="utf-8")
    monkeypatch.setenv("ATI_HASH_KEY", "test-secret-key")

    code = main(["analyze", str(input_path), "--output", str(output_path)])

    assert code == 2
    assert output_path.read_text(encoding="utf-8") == "previous-successful-output\n"
    assert "error:" in capsys.readouterr().err


def test_analyze_reports_missing_input_without_traceback(tmp_path, capsys) -> None:
    missing_path = tmp_path / "missing.jsonl"

    code = main(["analyze", str(missing_path)])

    assert code == 2
    assert "error:" in capsys.readouterr().err


def test_analyze_rejects_oversized_hash_key(tmp_path, monkeypatch, capsys) -> None:
    input_path = tmp_path / "access.jsonl"
    write_input(input_path)
    monkeypatch.setenv("ATI_HASH_KEY", "x" * 65)

    code = main(["analyze", str(input_path)])

    assert code == 2
    assert "64-byte" in capsys.readouterr().err


def test_analyze_respects_maximum_line_length(tmp_path, monkeypatch, capsys) -> None:
    input_path = tmp_path / "access.jsonl"
    write_input(input_path)
    monkeypatch.setenv("ATI_HASH_KEY", "test-secret-key")

    code = main(["analyze", str(input_path), "--max-line-characters", "10"])

    assert code == 2
    assert "character limit" in capsys.readouterr().err


def test_analyze_reports_bounded_session_capacity(tmp_path, monkeypatch, capsys) -> None:
    input_path = tmp_path / "access.jsonl"
    write_input(input_path)
    monkeypatch.setenv("ATI_HASH_KEY", "test-secret-key")

    code = main(["analyze", str(input_path), "--max-clients", "1"])

    assert code == 0
    summary = capsys.readouterr().err
    assert "active_clients=1" in summary
    assert "evicted_clients=1" in summary


def test_evaluate_reports_local_automation_metrics(tmp_path, capsys) -> None:
    detections_path = tmp_path / "detections.jsonl"
    labels_path = tmp_path / "labels.jsonl"
    detections_path.write_text(
        "\n".join(
            [
                json.dumps({"request_id": "a", "automation_score": 0.9}),
                json.dumps({"request_id": "b", "automation_score": 0.1}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    labels_path.write_text(
        "\n".join(
            [
                json.dumps({"request_id": "a", "automated": True}),
                json.dumps({"request_id": "b", "automated": False}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    code = main(["evaluate", str(detections_path), "--labels", str(labels_path)])

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["accuracy"] == 1.0
    assert result["evaluated_request_count"] == 2


def test_evaluate_manifest_requires_label_provenance(tmp_path, capsys) -> None:
    detections_path = tmp_path / "detections.jsonl"
    labels_path = tmp_path / "labels.jsonl"
    manifest_path = tmp_path / "manifest.json"
    detections_path.write_text(
        json.dumps({"request_id": "a", "automation_score": 0.9}) + "\n",
        encoding="utf-8",
    )
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "corpus_id": "owned-shadow-2026-08",
                "authorized": True,
                "collection_start": "2026-08-01T00:00:00Z",
                "collection_end": "2026-08-02T00:00:00Z",
                "split_strategies": [
                    "grouped_session_client",
                    "temporal_holdout",
                    "unseen_family_holdout",
                    "provider_ua_ablation",
                ],
                "known_sampling_biases": ["controlled-traffic-overrepresentation"],
            }
        ),
        encoding="utf-8",
    )
    labels_path.write_text(
        json.dumps({"request_id": "a", "automated": True}) + "\n",
        encoding="utf-8",
    )

    code = main(
        [
            "evaluate",
            str(detections_path),
            "--labels",
            str(labels_path),
            "--manifest",
            str(manifest_path),
        ]
    )

    assert code == 2
    assert "label_source" in capsys.readouterr().err

    labels_path.write_text(
        json.dumps(
            {
                "request_id": "a",
                "automated": True,
                "label_source": "controlled-generator",
                "label_confidence": 1.0,
                "corpus_id": "owned-shadow-2026-08",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    code = main(
        [
            "evaluate",
            str(detections_path),
            "--labels",
            str(labels_path),
            "--manifest",
            str(manifest_path),
        ]
    )

    assert code == 0
    assert json.loads(capsys.readouterr().out)["evaluated_request_count"] == 1

    labels_path.write_text(
        json.dumps(
            {
                "request_id": "a",
                "automated": True,
                "label_source": "controlled-generator",
                "label_confidence": 1.0,
                "corpus_id": "other-corpus",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    code = main(
        [
            "evaluate",
            str(detections_path),
            "--labels",
            str(labels_path),
            "--manifest",
            str(manifest_path),
        ]
    )

    assert code == 2
    assert "corpus_id" in capsys.readouterr().err

    labels_path.write_text(
        json.dumps(
            {
                "request_id": "a",
                "automated": True,
                "label_source": "controlled-generator",
                "label_confidence": 1.0,
                "corpus_id": "owned-shadow-2026-08",
                "raw_ip_address": "203.0.113.9",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    code = main(
        [
            "evaluate",
            str(detections_path),
            "--labels",
            str(labels_path),
            "--manifest",
            str(manifest_path),
        ]
    )

    assert code == 2
    assert "unsupported fields" in capsys.readouterr().err


def test_evaluate_rejects_oversized_detection_line(tmp_path, capsys) -> None:
    detections_path = tmp_path / "detections.jsonl"
    labels_path = tmp_path / "labels.jsonl"
    detections_path.write_text(
        json.dumps(
            {
                "request_id": "a",
                "automation_score": 0.9,
                "padding": "x" * 1_000_000,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    labels_path.write_text(
        json.dumps({"request_id": "a", "automated": True}) + "\n",
        encoding="utf-8",
    )

    code = main(["evaluate", str(detections_path), "--labels", str(labels_path)])

    assert code == 2
    assert "character limit" in capsys.readouterr().err


def test_evaluate_rejects_oversized_label_line(tmp_path, capsys) -> None:
    detections_path = tmp_path / "detections.jsonl"
    labels_path = tmp_path / "labels.jsonl"
    detections_path.write_text(
        json.dumps({"request_id": "a", "automation_score": 0.9}) + "\n",
        encoding="utf-8",
    )
    labels_path.write_text(
        json.dumps(
            {
                "request_id": "a",
                "automated": True,
                "padding": "x" * 1_000_000,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    code = main(["evaluate", str(detections_path), "--labels", str(labels_path)])

    assert code == 2
    assert "character limit" in capsys.readouterr().err


def test_run_creates_an_atomic_privacy_safe_local_artifact_directory(
    tmp_path, monkeypatch, capsys
) -> None:
    input_path = tmp_path / "access.jsonl"
    labels_path = tmp_path / "labels.jsonl"
    manifest_path = tmp_path / "manifest.json"
    run_dir = tmp_path / "run"
    write_input(input_path)
    monkeypatch.setenv("ATI_HASH_KEY", "test-secret-key")
    reference_detections = tmp_path / "reference-detections.jsonl"
    assert main(["analyze", str(input_path), "--output", str(reference_detections)]) == 0
    request_ids = [
        json.loads(line)["request_id"]
        for line in reference_detections.read_text(encoding="utf-8").splitlines()
    ]
    capsys.readouterr()
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "corpus_id": "owned-shadow-2026-08",
                "authorized": True,
                "collection_start": "2026-08-01T00:00:00Z",
                "collection_end": "2026-08-02T00:00:00Z",
                "split_strategies": [
                    "grouped_session_client",
                    "temporal_holdout",
                    "unseen_family_holdout",
                    "provider_ua_ablation",
                ],
                "known_sampling_biases": ["controlled-traffic-overrepresentation"],
            }
        ),
        encoding="utf-8",
    )
    labels_path.write_text(
        "\n".join(
            json.dumps(
                {
                    "request_id": request_id,
                    "automated": index == 0,
                    "label_source": "controlled-generator",
                    "label_confidence": 1.0,
                    "corpus_id": "owned-shadow-2026-08",
                }
            )
            for index, request_id in enumerate(request_ids)
        )
        + "\n",
        encoding="utf-8",
    )

    code = main(
        [
            "run",
            str(input_path),
            "--run-dir",
            str(run_dir),
            "--labels",
            str(labels_path),
            "--manifest",
            str(manifest_path),
        ]
    )

    assert code == 0
    run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert run["schema_version"] == 1
    assert run["corpus_id"] == "owned-shadow-2026-08"
    assert run["artifacts"]["detections"] == "detections.jsonl"
    assert run["artifacts"]["evaluation"] == "evaluation.json"
    evaluation = json.loads((run_dir / "evaluation.json").read_text(encoding="utf-8"))
    assert evaluation["evaluated_request_count"] == 2
    summary = (run_dir / "summary.md").read_text(encoding="utf-8")
    assert "Quality status: `ready`" in summary
    assert "Unlabeled detections: `0`" in summary
    assert "Unmatched labels: `0`" in summary
    serialized = "".join(
        path.read_text(encoding="utf-8") for path in run_dir.iterdir() if path.is_file()
    )
    assert "203.0.113" not in serialized
    assert "never-log-this" not in serialized
    assert "do-not-log" not in serialized
    assert "processed=2" in capsys.readouterr().err

    labels_path.write_text(
        json.dumps(
            {
                "request_id": request_ids[0],
                "automated": True,
                "label_source": "controlled-generator",
                "label_confidence": 1.0,
                "corpus_id": "owned-shadow-2026-08",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    review_run_dir = tmp_path / "review-required"
    assert (
        main(
            [
                "run",
                str(input_path),
                "--run-dir",
                str(review_run_dir),
                "--labels",
                str(labels_path),
                "--manifest",
                str(manifest_path),
            ]
        )
        == 0
    )
    assert "Quality status: `review-required`" in (review_run_dir / "summary.md").read_text(
        encoding="utf-8"
    )


def test_run_refuses_to_overwrite_an_existing_artifact_directory(tmp_path, capsys) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run.json").write_text("existing\n", encoding="utf-8")

    code = main(
        [
            "run",
            "unused.jsonl",
            "--run-dir",
            str(run_dir),
            "--labels",
            "unused-labels.jsonl",
            "--manifest",
            "unused-manifest.json",
        ]
    )

    assert code == 2
    assert (run_dir / "run.json").read_text(encoding="utf-8") == "existing\n"
    assert "already exists" in capsys.readouterr().err


def test_registry_validate_reports_curated_entry_count(capsys) -> None:
    code = main(["registry", "validate"])

    assert code == 0
    output = capsys.readouterr().out
    assert "valid" in output
    assert "entries=11" in output


def test_explain_rejects_oversized_detection_lines(tmp_path, capsys) -> None:
    input_path = tmp_path / "detections.jsonl"
    input_path.write_text(
        json.dumps({"request_id": "target", "padding": "x" * 64}) + "\n",
        encoding="utf-8",
    )

    code = main(
        [
            "explain",
            str(input_path),
            "--request-id",
            "target",
            "--max-line-characters",
            "10",
        ]
    )

    assert code == 2
    assert "character limit" in capsys.readouterr().err


def test_explain_pretty_prints_evidence(tmp_path, monkeypatch, capsys) -> None:
    input_path = tmp_path / "access.jsonl"
    output_path = tmp_path / "detections.jsonl"
    write_input(input_path)
    monkeypatch.setenv("ATI_HASH_KEY", "test-secret-key")
    assert main(["analyze", str(input_path), "--output", str(output_path)]) == 0
    capsys.readouterr()

    request_id = json.loads(output_path.read_text().splitlines()[0])["request_id"]
    code = main(["explain", str(output_path), "--request-id", request_id])

    assert code == 0
    output = capsys.readouterr().out
    assert "known-agent-ua-claim" in output
    assert "identity_confidence" in output


def write_pf2_corpus(path: Path) -> tuple[dict[str, bool], dict[str, str], dict[str, str]]:
    """Write an authorized ATI-PF-2 access log with two tasks and two windows."""

    labels: dict[str, bool] = {}
    tasks: dict[str, str] = {}
    windows: dict[str, str] = {}
    lines: list[str] = []
    for index in range(32):
        automated = index % 2 == 0
        session = "hmac-sha256:" + f"{index:064x}"
        labels[session] = automated
        tasks[session] = "task-detail" if index % 4 < 2 else "task-related"
        windows[session] = "2026-09-26-am" if index < 16 else "2026-09-26-pm"
        hour = 1 if index < 16 else 9
        second = 0.0
        for route in ("/lab/start", "/lab/page/landing", "/lab/page/catalog", "/lab/complete"):
            second += 0.2 if automated else 6.0
            moment = f"2026-09-26T{hour:02d}:{int(second) // 60:02d}:{int(second) % 60:02d}+00:00"
            lines.append(
                json.dumps(
                    {
                        "session_id": session,
                        "request_uri": route,
                        "request_method": "GET",
                        "status": 200,
                        "time_iso8601": moment,
                    },
                    sort_keys=True,
                )
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return labels, tasks, windows


def run_pf2_preflight(tmp_path: Path) -> tuple[Path, Path]:
    access_path = tmp_path / "access.jsonl"
    labels, tasks, windows = write_pf2_corpus(access_path)
    labels_path = tmp_path / "labels-by-session.json"
    tasks_path = tmp_path / "tasks-by-session.json"
    windows_path = tmp_path / "collection-windows.json"
    labels_path.write_text(json.dumps(labels, sort_keys=True), encoding="utf-8")
    tasks_path.write_text(json.dumps(tasks, sort_keys=True), encoding="utf-8")
    windows_path.write_text(json.dumps(windows, sort_keys=True), encoding="utf-8")
    model_path = tmp_path / "model.jsonl"
    split_path = tmp_path / "splits.jsonl"
    preflight_path = tmp_path / "preflight.json"
    code = main(
        [
            "pf2-preflight",
            str(access_path),
            "--labels-by-session",
            str(labels_path),
            "--tasks-by-session",
            str(tasks_path),
            "--collection-windows-by-session",
            str(windows_path),
            "--model-output",
            str(model_path),
            "--split-output",
            str(split_path),
            "--preflight-output",
            str(preflight_path),
            "--min-sessions-per-task-class",
            "4",
        ]
    )
    assert code == 0
    assert json.loads(preflight_path.read_text())["status"] == "ready-for-baseline"
    return model_path, split_path


def test_pf2_baseline_reports_the_ladder_for_a_ready_corpus(tmp_path, capsys) -> None:
    model_path, split_path = run_pf2_preflight(tmp_path)
    capsys.readouterr()
    output_path = tmp_path / "baseline.json"

    code = main(
        [
            "pf2-baseline",
            str(model_path),
            "--split-manifest",
            str(split_path),
            "--output",
            str(output_path),
            "--resamples",
            "32",
            "--seed",
            "3",
            "--target-false-positive-rate",
            "0.1",
        ]
    )

    assert code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary == {"output": str(output_path), "status": "evaluated"}
    report = json.loads(output_path.read_text())
    assert report["status"] == "evaluated"
    assert report["session_count"] == 32
    assert report["firewall"]["train_holdout_session_overlap_count"] == 0
    assert report["verdict"]["target_false_positive_rate"] == 0.1
    assert "hmac-sha256:" not in output_path.read_text()


def test_pf2_baseline_rejects_a_prohibited_model_column(tmp_path, capsys) -> None:
    model_path, split_path = run_pf2_preflight(tmp_path)
    capsys.readouterr()
    rows = [json.loads(line) for line in model_path.read_text().splitlines()]
    rows[0]["ua_provenance_bucket"] = "scripted-http"
    model_path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8"
    )
    output_path = tmp_path / "baseline.json"

    code = main(
        [
            "pf2-baseline",
            str(model_path),
            "--split-manifest",
            str(split_path),
            "--output",
            str(output_path),
            "--resamples",
            "4",
        ]
    )

    assert code == 2
    assert "prohibited column" in capsys.readouterr().err
    assert not output_path.exists()


def test_pf2_baseline_rejects_split_metadata_with_an_experiment_label(tmp_path, capsys) -> None:
    model_path, split_path = run_pf2_preflight(tmp_path)
    capsys.readouterr()
    rows = [json.loads(line) for line in split_path.read_text().splitlines()]
    rows[0]["family"] = "playwright"
    split_path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8"
    )
    output_path = tmp_path / "baseline.json"

    code = main(
        [
            "pf2-baseline",
            str(model_path),
            "--split-manifest",
            str(split_path),
            "--output",
            str(output_path),
            "--resamples",
            "4",
        ]
    )

    assert code == 2
    assert "unsupported field" in capsys.readouterr().err
    assert not output_path.exists()


def test_pf2_baseline_rejects_oversized_model_lines(tmp_path, capsys) -> None:
    model_path, split_path = run_pf2_preflight(tmp_path)
    capsys.readouterr()
    output_path = tmp_path / "baseline.json"

    code = main(
        [
            "pf2-baseline",
            str(model_path),
            "--split-manifest",
            str(split_path),
            "--output",
            str(output_path),
            "--max-line-characters",
            "10",
        ]
    )

    assert code == 2
    assert "character limit" in capsys.readouterr().err


def test_pf2_export_bigquery_writes_aggregate_tables_atomically(tmp_path, capsys) -> None:
    model_path, split_path = run_pf2_preflight(tmp_path)
    report_path = tmp_path / "baseline.json"
    assert (
        main(
            [
                "pf2-baseline",
                str(model_path),
                "--split-manifest",
                str(split_path),
                "--output",
                str(report_path),
                "--resamples",
                "16",
            ]
        )
        == 0
    )
    capsys.readouterr()
    export_dir = tmp_path / "export"

    code = main(
        [
            "pf2-export-bigquery",
            str(model_path),
            "--report",
            str(report_path),
            "--output-dir",
            str(export_dir),
            "--run-id",
            "run-2026-09-26",
            "--corpus-id",
            "controlled-pf2-2026-09",
            "--dataset",
            "ati_pf2",
            "--exported-at",
            "2026-09-26T12:00:00+00:00",
        ]
    )

    assert code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["output_dir"] == str(export_dir)
    assert "pf2_baseline_metrics" in summary["tables"]
    assert (export_dir / "ddl.sql").exists()
    assert (export_dir / "export.json").exists()
    for table in summary["tables"]:
        assert (export_dir / f"{table}.ndjson").exists()
        assert (export_dir / f"{table}.schema.json").exists()
    # No artifact may carry an opaque session pseudonym out of the local corpus.
    for artifact in export_dir.iterdir():
        assert "hmac-sha256:" not in artifact.read_text(encoding="utf-8")


def test_pf2_export_bigquery_refuses_an_existing_directory(tmp_path, capsys) -> None:
    model_path, split_path = run_pf2_preflight(tmp_path)
    report_path = tmp_path / "baseline.json"
    assert (
        main(
            [
                "pf2-baseline",
                str(model_path),
                "--split-manifest",
                str(split_path),
                "--output",
                str(report_path),
                "--resamples",
                "16",
            ]
        )
        == 0
    )
    capsys.readouterr()
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    code = main(
        [
            "pf2-export-bigquery",
            str(model_path),
            "--report",
            str(report_path),
            "--output-dir",
            str(export_dir),
            "--run-id",
            "run",
            "--corpus-id",
            "corpus",
            "--dataset",
            "ati_pf2",
        ]
    )

    assert code == 2
    assert "already exists" in capsys.readouterr().err


def test_pf2_export_bigquery_rejects_an_unsafe_dataset_name(tmp_path, capsys) -> None:
    model_path, split_path = run_pf2_preflight(tmp_path)
    report_path = tmp_path / "baseline.json"
    assert (
        main(
            [
                "pf2-baseline",
                str(model_path),
                "--split-manifest",
                str(split_path),
                "--output",
                str(report_path),
                "--resamples",
                "16",
            ]
        )
        == 0
    )
    capsys.readouterr()
    export_dir = tmp_path / "export"

    code = main(
        [
            "pf2-export-bigquery",
            str(model_path),
            "--report",
            str(report_path),
            "--output-dir",
            str(export_dir),
            "--run-id",
            "run",
            "--corpus-id",
            "corpus",
            "--dataset",
            "ati_pf2; DROP SCHEMA other",
        ]
    )

    assert code == 2
    assert "alphanumeric BigQuery dataset" in capsys.readouterr().err
    assert not export_dir.exists()
