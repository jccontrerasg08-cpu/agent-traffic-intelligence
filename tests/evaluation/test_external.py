"""The external check reads the Iliou layout and reports aggregates only.

Every archive here is synthetic: the real dataset's licence forbids committing it.
"""

from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agent_traffic_intelligence.cli import main
from agent_traffic_intelligence.evaluation.external import (
    ExternalDatasetError,
    Navigation,
    auc,
    iliou_report,
    long_pages,
    parse_navigation,
    session_features,
)

_START = datetime(2019, 11, 1, 10, 0, tzinfo=UTC)
_PAGES = {"/content/short.php": 900, "/content/long.php": 9000, "/": 1200}


def _line(session: str, at: datetime, path: str, size: int, method: str = "GET") -> str:
    stamp = at.strftime("%d/%b/%Y:%H:%M:%S %z")
    return (
        f'- - [{stamp}] "{method} {path} HTTP/1.1" 200 {size} "http://lab/" '
        f'{session} "Mozilla/5.0 (X11; Linux x86_64)"'
    )


def _session(session: str, long_dwell: float, short_dwell: float, offset: int) -> list[str]:
    at = _START + timedelta(hours=offset)
    lines = []
    for step in range(12):
        path = "/content/long.php" if step % 2 else "/content/short.php"
        lines.append(_line(session, at, path, _PAGES[path]))
        lines.append(_line(session, at, "/css/main.css", 700))
        lines.append(_line(session, at, "/storage/store_mousemv_db.php", 0, method="POST"))
        at += timedelta(seconds=long_dwell if step % 2 else short_dwell)
    return lines


def _archive(tmp_path: Path) -> Path:
    # People dwell longer on long pages; moderate bots do not; advanced bots overdo it.
    people = {f"h{index}": (30 + index, 15) for index in range(6)}
    moderate = {f"m{index}": (12, 12 + index) for index in range(6)}
    advanced = {f"a{index}": (60 + index, 15) for index in range(6)}
    path = tmp_path / "dataset.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for phase in ("phase1", "phase2"):
            logs: list[str] = []
            for offset, (session, (long_dwell, short_dwell)) in enumerate(
                {**people, **moderate, **advanced}.items()
            ):
                logs += _session(session, long_dwell, short_dwell, offset)
            archive.writestr(f"{phase}/data/web_logs/humans/access_1.log", "\n".join(logs))
            suffix = "_0" if phase == "phase2" else ""
            humans = [f"{s}{suffix} human" for s in people]
            archive.writestr(
                f"{phase}/annotations/humans_and_advanced_bots/train",
                "\n".join(humans + [f"{s}{suffix} advanced_bot" for s in advanced]) + "\n\n",
            )
            archive.writestr(
                f"{phase}/annotations/humans_and_moderate_bots/train",
                "\n".join(humans + [f"{s}{suffix} moderate_bot" for s in moderate]),
            )
    return path


def test_only_page_navigations_are_read() -> None:
    at = _START
    assert parse_navigation(_line("s1", at, "/content/a.php", 10)) == Navigation(
        "s1", at.timestamp(), "/content/a.php", 10
    )
    assert parse_navigation(_line("s1", at, "/", 10)) is not None
    assert parse_navigation(_line("s1", at, "/css/main.css", 10)) is None
    assert parse_navigation(_line("s1", at, "/content/a.php", 10, method="POST")) is None
    assert parse_navigation(_line("-", at, "/content/a.php", 10)) is None
    assert parse_navigation("garbage") is None


def test_auc_counts_ties_as_half() -> None:
    assert auc([2.0, 3.0], [1.0]) == 1.0
    assert auc([1.0], [1.0]) == 0.5
    with pytest.raises(ValueError):
        auc([], [1.0])


def test_long_pages_are_those_above_the_median_size() -> None:
    navigations = [
        Navigation("s", 0, path, size)
        for path, size in (("/a", 1), ("/b", 5), ("/c", 9), ("/c", 9))
    ]
    assert long_pages(navigations) == frozenset({"/c"})


def test_a_session_without_both_loads_has_no_features() -> None:
    navigations = [Navigation("s", float(t), "/a", 1) for t in (0, 10, 20)]
    assert session_features(navigations, frozenset({"/b"})) is None


def test_the_report_separates_each_comparison(tmp_path: Path) -> None:
    report = iliou_report(_archive(tmp_path))

    moderate = report["comparisons"]["phase1-moderate"]["features"]["dwell_ratio"]
    advanced = report["comparisons"]["phase1-advanced"]["features"]["dwell_ratio"]
    assert report["licence"] == "CC BY-NC-SA 4.0"
    assert report["comparisons"]["phase2-advanced"]["human_sessions"] == 6
    assert moderate["auc_human_above_bot"] == 1.0
    # Advanced bots dwell more in proportion to length than people do.
    assert advanced["auc_human_above_bot"] == 0.0
    assert advanced["bot_median"] > advanced["human_median"] > moderate["bot_median"]


def test_the_report_holds_no_session_identifier_or_path(tmp_path: Path) -> None:
    serialized = json.dumps(iliou_report(_archive(tmp_path)))

    for forbidden in ("h0", "a0", "m0", "/content/", "Mozilla"):
        assert forbidden not in serialized


def test_an_archive_without_annotations_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "empty.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("README.txt", "nothing here")

    with pytest.raises(ExternalDatasetError, match="no annotations"):
        iliou_report(path)


def test_a_file_that_is_not_an_archive_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "dataset.zip"
    path.write_text("not a zip", encoding="utf-8")

    with pytest.raises(ExternalDatasetError, match="cannot open"):
        iliou_report(path)


def test_cli_writes_the_report(tmp_path: Path, capsys) -> None:
    output = tmp_path / "report.json"

    code = main(
        ["external-check", "--archive", str(_archive(tmp_path)), "--output", str(output)]
    )

    assert code == 0
    assert json.loads(output.read_text())["dataset"] == "iliou-web-bot-detection"
    assert "phase1-advanced" in capsys.readouterr().out


def test_cli_refuses_a_bad_archive_and_writes_nothing(tmp_path: Path, capsys) -> None:
    bad = tmp_path / "bad.zip"
    bad.write_text("nope", encoding="utf-8")
    output = tmp_path / "report.json"

    assert main(["external-check", "--archive", str(bad), "--output", str(output)]) == 2
    assert not output.exists()
    assert "error:" in capsys.readouterr().err
