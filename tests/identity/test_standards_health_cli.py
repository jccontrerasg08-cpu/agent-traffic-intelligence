from __future__ import annotations

import json

import pytest

from agent_traffic_intelligence import cli
from agent_traffic_intelligence.identity.standards_health import (
    DraftHealth,
    DraftHealthStatus,
    DraftPin,
    StandardsHealthOperationalError,
    StandardsHealthReport,
)


def report(*, review_required: bool) -> StandardsHealthReport:
    pin = DraftPin.from_pinned("draft-example-widget-03")
    status = (
        DraftHealthStatus.REVIEW_REQUIRED
        if review_required
        else DraftHealthStatus.CURRENT
    )
    reasons = ("new revision observed",) if review_required else ()
    return StandardsHealthReport(
        drafts=(
            DraftHealth(
                pin=pin,
                observed_revision="04" if review_required else "03",
                status=status,
                reasons=reasons,
            ),
        )
    )


def test_standards_health_current_prints_json_and_returns_zero(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "check_pinned_drafts", lambda *, client: report(review_required=False))

    assert cli.main(["standards", "health"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "drafts": [
            {
                "observed_revision": "03",
                "pinned": "draft-example-widget-03",
                "reasons": [],
                "status": "current",
            }
        ],
        "review_required": False,
    }


def test_standards_health_review_required_returns_one(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "check_pinned_drafts", lambda *, client: report(review_required=True))

    assert cli.main(["standards", "health"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["review_required"] is True
    assert payload["drafts"][0]["status"] == "review_required"
    assert payload["drafts"][0]["reasons"] == ["new revision observed"]


def test_standards_health_operational_error_returns_two_without_traceback(
    monkeypatch,
    capsys,
) -> None:
    def fail(*, client):
        raise StandardsHealthOperationalError("Datatracker transport failed: TimeoutError")

    monkeypatch.setattr(cli, "check_pinned_drafts", fail)

    assert cli.main(["standards", "health"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "standards health failed" in captured.err
    assert "TimeoutError" in captured.err
    assert "Traceback" not in captured.err


def test_standards_health_is_explicit_and_does_not_change_analyze_parser(monkeypatch) -> None:
    called = False

    def fake_check(*, client):
        nonlocal called
        called = True
        return report(review_required=False)

    monkeypatch.setattr(cli, "check_pinned_drafts", fake_check)

    parser = cli._parser()
    args = parser.parse_args(["analyze", "-"])
    assert args.command == "analyze"
    assert called is False
