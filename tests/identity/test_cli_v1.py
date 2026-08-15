from __future__ import annotations

import json
from pathlib import Path

from agent_traffic_intelligence import cli


def input_record() -> dict[str, object]:
    return {
        "time_iso8601": "2026-08-14T08:00:00+00:00",
        "remote_addr": "192.0.2.42",
        "request_method": "GET",
        "request_uri": "/docs?secret=drop-me",
        "status": 200,
        "body_bytes_sent": 100,
        "server_protocol": "HTTP/2.0",
        "http_user_agent": "GPTBot/1.2",
    }


def write_input(path: Path) -> None:
    path.write_text(json.dumps(input_record()) + "\n", encoding="utf-8")


def test_default_analyze_keeps_v0_shape(tmp_path: Path, monkeypatch) -> None:
    input_path = tmp_path / "access.jsonl"
    output_path = tmp_path / "out.jsonl"
    write_input(input_path)
    monkeypatch.setenv("ATI_HASH_KEY", "test-key")

    assert cli.main(["analyze", str(input_path), "--output", str(output_path)]) == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert "verification" not in payload


def test_offline_identity_verification_emits_versioned_payload(tmp_path: Path, monkeypatch) -> None:
    input_path = tmp_path / "access.jsonl"
    output_path = tmp_path / "out.jsonl"
    write_input(input_path)
    monkeypatch.setenv("ATI_HASH_KEY", "test-key")
    monkeypatch.setenv("ATI_SOURCE_CACHE", str(tmp_path / "cache"))

    assert (
        cli.main(
            [
                "analyze",
                str(input_path),
                "--output",
                str(output_path),
                "--verify-identity",
            ]
        )
        == 0
    )
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["verification"]["schema_version"] == 1
    assert payload["verification"]["state"] == "claimed"
    serialized = json.dumps(payload)
    assert "192.0.2.42" not in serialized
    assert "secret=drop-me" not in serialized


def test_sources_status_and_validate_are_offline(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("ATI_SOURCE_CACHE", str(tmp_path / "cache"))
    assert cli.main(["sources", "status"]) == 0
    assert cli.main(["sources", "validate"]) == 0
    output = capsys.readouterr().out
    assert "cached" in output
    assert "valid cached sources" in output


def test_sources_refresh_is_explicit_and_provider_scoped(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ATI_SOURCE_CACHE", str(tmp_path / "cache"))
    captured: dict[str, str | None] = {}

    def fake_refresh(cache, *, provider=None, fetcher=None):
        captured["provider"] = provider
        return 2, 1

    monkeypatch.setattr(cli, "refresh_sources", fake_refresh)
    assert cli.main(["sources", "refresh", "--provider", "openai"]) == 0
    assert captured["provider"] == "openai"
