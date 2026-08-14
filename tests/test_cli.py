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

    code = main(["explain", str(output_path), "--request-id", json.loads(output_path.read_text().splitlines()[0])["request_id"]])

    assert code == 0
    output = capsys.readouterr().out
    assert "known-agent-ua-claim" in output
    assert "identity_confidence" in output
