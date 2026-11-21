"""External check of timing features on a public dataset with controlled labels.

The dataset is Iliou et al.'s web bot detection dataset (m4d.iti.gr), distributed under
CC BY-NC-SA 4.0. Its labels come from how each session was produced: people browsing, or
bots the authors drove, "moderate" or "advanced". That makes it the closest public match
to the ATI-PF-2 protocol. The licence forbids redistributing it with this Apache-licensed
code, so the archive is never committed: the operator downloads it and passes its path.

The check reads only page navigations from the web logs: a GET answered 200 for `/` or a
`/content/*.php` page, with its time to the second and its response size. Dwell is the
time to the next navigation. A page counts as `long` when its median response size is
above the median over pages, a rough stand-in for the reading load the laboratory's
catalogue declares. The report holds only aggregates: per comparison, class counts,
medians and the area under the ROC curve of each feature. No session identifier, path,
address or User-Agent leaves this module.
"""

from __future__ import annotations

import re
import statistics
import zipfile
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from typing import Any

ILIOU_SOURCE = "https://m4d.iti.gr/web-bot-detection-dataset/"
ILIOU_LICENCE = "CC BY-NC-SA 4.0"
ILIOU_COMPARISONS: tuple[tuple[str, str, str], ...] = (
    ("phase1-moderate", "phase1", "phase1/annotations/humans_and_moderate_bots/"),
    ("phase1-advanced", "phase1", "phase1/annotations/humans_and_advanced_bots/"),
    ("phase2-advanced", "phase2", "phase2/annotations/humans_and_advanced_bots/"),
)
_MAX_MEMBER_BYTES = 256 * 1024 * 1024
_MAX_DWELL_SECONDS = 600.0
_NAVIGATION = re.compile(
    r'\[(?P<time>[^\]]+)\] "GET (?P<path>/(?:content/[^ ?"]*\.php)?)(?:\?[^ "]*)? [^"]*" '
    r'200 (?P<size>\d+) "[^"]*" (?P<session>\S+) '
)
FEATURES = ("dwell_ratio", "median_gap", "gap_cv", "max_gap")


class ExternalDatasetError(ValueError):
    """Raised when the archive does not have the expected layout."""


@dataclass(frozen=True)
class Navigation:
    session: str
    at: float
    path: str
    size: int


def parse_navigation(line: str) -> Navigation | None:
    """Return the page navigation a log line records, or None for anything else."""

    match = _NAVIGATION.search(line)
    if match is None or match["session"] == "-":
        return None
    at = datetime.strptime(match["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
    return Navigation(match["session"], at, match["path"], int(match["size"]))


def auc(positives: Sequence[float], negatives: Sequence[float]) -> float:
    """Probability that a positive outscores a negative, ties counting one half."""

    if not positives or not negatives:
        raise ValueError("both classes need at least one value")
    wins = sum((p > n) + 0.5 * (p == n) for p in positives for n in negatives)
    return wins / (len(positives) * len(negatives))


def session_features(
    navigations: Sequence[Navigation], long_pages: frozenset[str]
) -> dict[str, float] | None:
    """Return one session's features, or None when it has too few navigations."""

    ordered = sorted(navigations, key=lambda navigation: navigation.at)
    dwell: dict[bool, list[float]] = {True: [], False: []}
    gaps: list[float] = []
    for page, following in pairwise(ordered):
        gap = following.at - page.at
        if 0 < gap < _MAX_DWELL_SECONDS:
            dwell[page.path in long_pages].append(gap)
            gaps.append(gap)
    if len(gaps) < 2 or not dwell[True] or not dwell[False]:
        return None
    mean = statistics.fmean(gaps)
    return {
        "dwell_ratio": statistics.fmean(dwell[True]) / statistics.fmean(dwell[False]),
        "median_gap": statistics.median(gaps),
        "gap_cv": statistics.pstdev(gaps) / mean,
        "max_gap": max(gaps),
    }


def long_pages(navigations: Iterable[Navigation]) -> frozenset[str]:
    """Pages whose median response size is above the median over all pages."""

    sizes: dict[str, list[int]] = defaultdict(list)
    for navigation in navigations:
        sizes[navigation.path].append(navigation.size)
    medians = {path: statistics.median(values) for path, values in sizes.items()}
    if not medians:
        return frozenset()
    cut = statistics.median(medians.values())
    return frozenset(path for path, value in medians.items() if value > cut)


def compare(
    labels: Mapping[str, str], navigations: Mapping[str, Sequence[Navigation]]
) -> dict[str, Any]:
    """Aggregate one human-versus-bot comparison. AUC is P(human scores above bot)."""

    pages = long_pages(n for session in labels for n in navigations.get(session, ()))
    rows: dict[bool, list[dict[str, float]]] = {True: [], False: []}
    for session, label in sorted(labels.items()):
        features = session_features(navigations.get(session, ()), pages)
        if features is not None:
            rows[label == "human"].append(features)
    humans, bots = rows[True], rows[False]
    if not humans or not bots:
        raise ExternalDatasetError("a comparison needs sessions of both classes")
    return {
        "human_sessions": len(humans),
        "bot_sessions": len(bots),
        "pages": len({n.path for s in labels for n in navigations.get(s, ())}),
        "features": {
            name: {
                "human_median": round(statistics.median(r[name] for r in humans), 3),
                "bot_median": round(statistics.median(r[name] for r in bots), 3),
                "auc_human_above_bot": round(
                    auc([r[name] for r in humans], [r[name] for r in bots]), 3
                ),
            }
            for name in FEATURES
        },
    }


def _read(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    if info.file_size > _MAX_MEMBER_BYTES:
        raise ExternalDatasetError(f"archive member is too large: {info.filename}")
    return archive.read(info).decode("utf-8", errors="replace")


def _labels(archive: zipfile.ZipFile, prefix: str, *, strip_suffix: bool) -> dict[str, str]:
    labels: dict[str, str] = {}
    for info in archive.infolist():
        if not info.filename.startswith(prefix) or info.is_dir():
            continue
        for line in _read(archive, info).splitlines():
            fields = line.split()
            if len(fields) < 2:
                continue
            session = fields[0].rsplit("_", 1)[0] if strip_suffix else fields[0]
            labels[session] = fields[1]
    return labels


def _navigations(archive: zipfile.ZipFile, phase: str) -> dict[str, list[Navigation]]:
    sessions: dict[str, list[Navigation]] = defaultdict(list)
    prefix = f"{phase}/data/web_logs/"
    for info in archive.infolist():
        if info.filename.startswith(prefix) and info.filename.endswith(".log"):
            for line in _read(archive, info).splitlines():
                navigation = parse_navigation(line)
                if navigation is not None:
                    sessions[navigation.session].append(navigation)
    return sessions


def iliou_report(path: Path) -> dict[str, Any]:
    """Run every comparison on the archive at `path` and return an aggregate report."""

    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ExternalDatasetError(f"cannot open the dataset archive: {exc}") from exc
    with archive:
        cache: dict[str, dict[str, list[Navigation]]] = {}
        comparisons = {}
        for name, phase, prefix in ILIOU_COMPARISONS:
            labels = _labels(archive, prefix, strip_suffix=phase == "phase2")
            if not labels:
                raise ExternalDatasetError(f"no annotations under {prefix}")
            if phase not in cache:
                cache[phase] = _navigations(archive, phase)
            comparisons[name] = compare(labels, cache[phase])
    return {
        "dataset": "iliou-web-bot-detection",
        "source": ILIOU_SOURCE,
        "licence": ILIOU_LICENCE,
        "fixture": False,
        "reading_load_proxy": "page median response size above the median over pages",
        "comparisons": comparisons,
    }
