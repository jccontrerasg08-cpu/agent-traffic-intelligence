from __future__ import annotations

import json

from agent_traffic_intelligence import evaluation
from agent_traffic_intelligence.cli import main as evaluation_cli_main


def test_stratified_evaluation_reports_holdouts_without_raw_session_or_ua() -> None:
    evaluate = getattr(evaluation, "evaluate_stratified_automation_scores", None)
    assert callable(evaluate)

    detections = [
        {"request_id": "a", "automation_score": 0.9},
        {"request_id": "b", "automation_score": 0.8},
        {"request_id": "c", "automation_score": 0.1},
        {"request_id": "d", "automation_score": 0.2},
    ]
    labels = {"a": True, "b": True, "c": False, "d": True}
    metadata = {
        "a": {
            "session_id": "hmac-sha256:" + "a" * 64,
            "family": "playwright",
            "provider": "none",
            "ua_bucket": "headless-chrome",
            "time_iso8601": "2026-08-21T09:00:00+00:00",
        },
        "b": {
            "session_id": "hmac-sha256:" + "a" * 64,
            "family": "playwright",
            "provider": "none",
            "ua_bucket": "headless-chrome",
            "time_iso8601": "2026-08-21T09:01:00+00:00",
        },
        "c": {
            "session_id": "hmac-sha256:" + "b" * 64,
            "family": "human-chrome",
            "provider": "none",
            "ua_bucket": "chrome",
            "time_iso8601": "2026-08-22T09:00:00+00:00",
        },
        "d": {
            "session_id": "hmac-sha256:" + "c" * 64,
            "family": "selenium",
            "provider": "none",
            "ua_bucket": "chrome",
            "time_iso8601": "2026-08-23T09:00:00+00:00",
        },
    }

    result = evaluate(detections, labels, metadata, threshold=0.5)

    assert result["integrity"] == {
        "missing_metadata_count": 0,
        "session_group_count": 3,
        "sessionless_request_count": 0,
    }
    assert result["overall"]["false_negative"] == 1
    assert result["splits"]["unseen_family_holdout"]["selenium"]["false_negative"] == 1
    assert result["splits"]["temporal_holdout"]["2026-08-23"]["evaluated_request_count"] == 1
    assert result["splits"]["provider_ua_ablation"]["provider=none|ua=chrome"][
        "evaluated_request_count"
    ] == 2
    serialized = json.dumps(result, sort_keys=True)
    assert "hmac-sha256:" not in serialized
    assert "HeadlessChrome" not in serialized


def test_stratified_evaluate_cli_requires_manifest_and_writes_aggregate_output(
    tmp_path, capsys
) -> None:
    detections = tmp_path / "detections.jsonl"
    labels = tmp_path / "labels.jsonl"
    metadata = tmp_path / "metadata.jsonl"
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "stratified.json"
    session_id = "hmac-sha256:" + "e" * 64
    detections.write_text(
        json.dumps({"request_id": "record-1", "automation_score": 0.9}) + "\n",
        encoding="utf-8",
    )
    labels.write_text(
        json.dumps(
            {
                "request_id": "record-1",
                "automated": True,
                "label_source": "controlled-campaign",
                "label_confidence": 1.0,
                "corpus_id": "generalization-2026-08",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    metadata.write_text(
        json.dumps(
            {
                "request_id": "record-1",
                "session_id": session_id,
                "family": "playwright",
                "provider": "none",
                "ua_bucket": "headless-chrome",
                "time_iso8601": "2026-08-21T09:00:00+00:00",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "corpus_id": "generalization-2026-08",
                "authorized": True,
                "collection_start": "2026-08-21T09:00:00+00:00",
                "collection_end": "2026-08-22T09:00:00+00:00",
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

    try:
        code = evaluation_cli_main(
            [
                "evaluate-stratified",
                str(detections),
                "--labels",
                str(labels),
                "--metadata",
                str(metadata),
                "--manifest",
                str(manifest),
                "--output",
                str(output),
            ]
        )
    except SystemExit as exc:
        code = exc.code

    assert code == 0
    serialized = output.read_text(encoding="utf-8")
    assert json.loads(serialized)["integrity"]["session_group_count"] == 1
    assert session_id not in serialized
    assert session_id not in capsys.readouterr().out
