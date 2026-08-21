from __future__ import annotations

import importlib
import json

import pytest

from agent_traffic_intelligence import cli


def _protocol_module():
    try:
        return importlib.import_module("agent_traffic_intelligence.campaign_protocol")
    except ModuleNotFoundError:
        pytest.fail("campaign protocol module is not implemented")


def test_build_navigation_plan_is_closed_privacy_safe_and_split_ready() -> None:
    protocol = _protocol_module()
    plan = protocol.build_navigation_campaign_plan(
        campaign_id="owned-general-2026-08-21-browser",
        corpus_id="generalization-2026-08",
        families={"playwright": "HeadlessChrome", "human-chrome": "Chrome"},
        sessions_per_family=10,
    )

    assert plan["schema_version"] == 1
    assert plan["protocol"] == "session-navigation-v1"
    assert plan["sessions_per_family"] == 10
    assert plan["routes"] == [
        {"method": "GET", "path": "/lab/start"},
        {"method": "GET", "path": "/lab/page/landing"},
        {"method": "GET", "path": "/lab/assets/site.css"},
        {"method": "GET", "path": "/lab/page/catalog"},
        {"method": "HEAD", "path": "/lab/page/detail"},
        {"method": "GET", "path": "/lab/missing"},
    ]
    assert plan["prohibited_fields"] == [
        "authorization",
        "body",
        "cookie",
        "ip_address",
        "query_string",
    ]
    assert plan["split_requirements"] == [
        "grouped_session_client",
        "temporal_holdout",
        "unseen_family_holdout",
        "provider_ua_ablation",
    ]


def test_validate_campaign_runtime_reports_mismatch_and_missing_session() -> None:
    protocol = _protocol_module()
    rows = [
        {
            "request_id": "a" * 32,
            "ati_campaign_id": "owned-general-2026-08-21-browser",
            "session_id": "hmac-sha256:" + "1" * 64,
            "http_user_agent": "Mozilla/5.0 HeadlessChrome/140.0",
        },
        {
            "request_id": "b" * 32,
            "ati_campaign_id": "owned-general-2026-08-21-browser",
            "session_id": "hmac-sha256:" + "2" * 64,
            "http_user_agent": "curl/8.5.0",
        },
        {
            "request_id": "c" * 32,
            "ati_campaign_id": "owned-general-2026-08-21-browser",
            "http_user_agent": "Mozilla/5.0 HeadlessChrome/140.0",
        },
    ]

    result = protocol.validate_campaign_runtime(
        rows,
        campaign_id="owned-general-2026-08-21-browser",
        expected_ua_token="HeadlessChrome",
    )

    assert result == {
        "campaign_id": "owned-general-2026-08-21-browser",
        "observed_request_count": 3,
        "observed_session_count": 2,
        "compatible_request_count": 1,
        "incompatible_request_count": 1,
        "missing_session_count": 1,
        "status": "review-required",
    }


def test_campaign_plan_cli_writes_an_atomic_json_artifact(tmp_path) -> None:
    output = tmp_path / "plan.json"

    assert (
        cli.main(
            [
                "campaign",
                "plan",
                "--campaign-id",
                "owned-general-2026-08-21-browser",
                "--corpus-id",
                "generalization-2026-08",
                "--family",
                "playwright=HeadlessChrome",
                "--sessions-per-family",
                "10",
                "--output",
                str(output),
            ]
        )
        == 0
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["families"] == [{"name": "playwright", "ua_token": "HeadlessChrome"}]


def test_campaign_runtime_validate_cli_writes_only_aggregate_summary(tmp_path, capsys) -> None:
    input_path = tmp_path / "access.jsonl"
    output = tmp_path / "runtime.json"
    session_id = "hmac-sha256:" + "f" * 64
    input_path.write_text(
        json.dumps(
            {
                "request_id": "d" * 32,
                "ati_campaign_id": "owned-general-2026-08-21-browser",
                "session_id": session_id,
                "http_user_agent": "Mozilla/5.0 HeadlessChrome/140.0",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    assert (
        cli.main(
            [
                "campaign",
                "runtime-validate",
                str(input_path),
                "--campaign-id",
                "owned-general-2026-08-21-browser",
                "--expected-ua-token",
                "HeadlessChrome",
                "--output",
                str(output),
            ]
        )
        == 0
    )

    serialized = output.read_text(encoding="utf-8")
    assert json.loads(serialized)["status"] == "ready"
    assert session_id not in serialized
    assert "HeadlessChrome" not in serialized
    assert session_id not in capsys.readouterr().out
