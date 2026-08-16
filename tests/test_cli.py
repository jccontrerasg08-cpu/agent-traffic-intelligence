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


def test_registry_validate_reports_curated_entry_count(capsys) -> None:
    code = main(["registry", "validate"])

    assert code == 0
    output = capsys.readouterr().out
    assert "valid" in output
    assert "entries=11" in output


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
