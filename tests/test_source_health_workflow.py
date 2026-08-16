from __future__ import annotations

from pathlib import Path


def workflow_text() -> str:
    return Path(".github/workflows/source-health.yml").read_text(encoding="utf-8")


def test_source_health_remains_schedule_and_manual_only() -> None:
    workflow = workflow_text()

    assert "schedule:" in workflow
    assert "workflow_dispatch:" in workflow
    assert "\n  pull_request:" not in workflow
    assert "\n  pull_request_target:" not in workflow
    assert "\n  push:" not in workflow


def test_source_health_keeps_read_only_repository_permissions() -> None:
    workflow = workflow_text()

    assert "permissions:\n  contents: read" in workflow
    assert "contents: write" not in workflow
    assert "pull-requests: write" not in workflow
    assert "issues: write" not in workflow


def test_source_health_checks_datatracker_standards_drift() -> None:
    workflow = workflow_text()

    assert "ati standards health" in workflow
