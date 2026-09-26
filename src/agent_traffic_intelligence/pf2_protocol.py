"""Privacy-first session dataset preparation for the ATI-PF-2 laboratory protocol.

This module accepts local, authorized controlled-session records. Exact timestamps and
opaque session identifiers are used only in memory to group and order a session; they
are never emitted in model rows. Campaign, family, executor, user-agent provenance,
and task assignment are deliberately unavailable to the model.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise
from types import MappingProxyType
from typing import Any

_SESSION_ID_PREFIX = "hmac-sha256:"
_SESSION_ID_HEX_LENGTH = 64
_APPROVED_ROUTES = {
    "/lab/start": "start",
    "/lab/page/landing": "landing",
    "/lab/page/catalog": "catalog",
    "/lab/page/detail": "detail",
    "/lab/page/related": "related",
    "/lab/complete": "complete",
    "/lab/assets/site.css": "asset",
    "/lab/assets/pixel.svg": "asset",
}
_ROUTE_CATEGORIES = tuple(sorted(set(_APPROVED_ROUTES.values())))
_DELAY_BIN_NAMES = (
    "delay_bin_under_1_count",
    "delay_bin_1_to_4_count",
    "delay_bin_4_to_16_count",
    "delay_bin_16_plus_count",
)
_ROUTE_COUNT_FEATURES = tuple(f"route_{category}_count" for category in _ROUTE_CATEGORIES)
_TRANSITION_FEATURES = tuple(
    f"transition_{previous}_to_{current}_count"
    for previous in _ROUTE_CATEGORIES
    for current in _ROUTE_CATEGORIES
)

PF2_TARGET_NAME = "automated"
"""Name of the only permitted ATI-PF-2 model target column."""

PF2_FEATURE_FAMILIES: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "session_navigation": (
            "session_request_count",
            "duplicate_route_category_count",
            "completion",
            *_ROUTE_COUNT_FEATURES,
        ),
        "route_transition": _TRANSITION_FEATURES,
        "http_method_status": (
            "method_head_count",
            "status_2xx_count",
            "status_4xx_count",
        ),
        "coarsened_tempo": ("session_duration_bucket", *_DELAY_BIN_NAMES),
    }
)
"""Permitted feature families from the controlled-corpus feature contract."""


def pf2_feature_names() -> tuple[str, ...]:
    """Return the fixed permitted ATI-PF-2 feature vocabulary in a stable order."""

    return tuple(name for family in PF2_FEATURE_FAMILIES.values() for name in family)


def is_pf2_session_id(value: object) -> bool:
    """Report whether a value is an opaque ATI-PF-2 session pseudonym."""

    return (
        isinstance(value, str)
        and value.startswith(_SESSION_ID_PREFIX)
        and len(value) == len(_SESSION_ID_PREFIX) + _SESSION_ID_HEX_LENGTH
        and all(character in "0123456789abcdef" for character in value[len(_SESSION_ID_PREFIX) :])
    )


class PF2ProtocolError(ValueError):
    """Raised when a controlled corpus cannot produce a privacy-safe ML table."""


@dataclass(frozen=True, slots=True)
class PF2PreparedDataset:
    """Model rows, separate split rows, and preflight results for a local corpus."""

    model_rows: tuple[dict[str, int | bool], ...]
    split_rows: tuple[dict[str, int | str], ...]
    preflight: dict[str, int | str]


def _is_session_id(value: object) -> bool:
    return is_pf2_session_id(value)


def _parse_record(record: Mapping[str, Any]) -> tuple[str, str, str, int, datetime]:
    session_id = record.get("session_id")
    if not isinstance(session_id, str) or not _is_session_id(session_id):
        raise PF2ProtocolError("record session_id must be an opaque HMAC pseudonym")
    path = record.get("request_uri")
    if not isinstance(path, str):
        raise PF2ProtocolError("record path must be an eligible ATI-PF-2 route")
    category = _APPROVED_ROUTES.get(path)
    if category is None:
        raise PF2ProtocolError("record path must be an eligible ATI-PF-2 route")
    method = record.get("request_method")
    if not isinstance(method, str) or method not in {"GET", "HEAD"}:
        raise PF2ProtocolError("record request_method must be GET or HEAD")
    status = record.get("status")
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        raise PF2ProtocolError("record status must be an HTTP status integer")
    timestamp = record.get("time_iso8601")
    if not isinstance(timestamp, str):
        raise PF2ProtocolError("record time_iso8601 must be an ISO 8601 timestamp")
    try:
        observed_at = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise PF2ProtocolError("record time_iso8601 must be an ISO 8601 timestamp") from exc
    if observed_at.tzinfo is None:
        raise PF2ProtocolError("record time_iso8601 must include a timezone")
    return session_id, category, method, status, observed_at


def _delay_bin_name(seconds: float) -> str:
    if seconds < 1:
        return _DELAY_BIN_NAMES[0]
    if seconds < 4:
        return _DELAY_BIN_NAMES[1]
    if seconds < 16:
        return _DELAY_BIN_NAMES[2]
    return _DELAY_BIN_NAMES[3]


def _duration_bucket(duration_seconds: float) -> int:
    if duration_seconds < 4:
        return 0
    if duration_seconds < 16:
        return 1
    if duration_seconds < 64:
        return 2
    return 3


def _empty_feature_row() -> dict[str, int | bool]:
    row: dict[str, int | bool] = dict.fromkeys(pf2_feature_names(), 0)
    row["completion"] = False
    return row


def _session_features(
    observations: list[tuple[str, str, int, datetime]], *, automated: bool
) -> dict[str, int | bool]:
    ordered = sorted(observations, key=lambda observation: observation[3])
    row = _empty_feature_row()
    categories = [category for category, _, _, _ in ordered]
    row["session_request_count"] = len(ordered)
    row["completion"] = "complete" in categories
    counts = Counter(categories)
    for category, count in counts.items():
        row[f"route_{category}_count"] = count
    row["duplicate_route_category_count"] = sum(count - 1 for count in counts.values())
    row["method_head_count"] = sum(method == "HEAD" for _, method, _, _ in ordered)
    row["status_2xx_count"] = sum(200 <= status < 300 for _, _, status, _ in ordered)
    row["status_4xx_count"] = sum(400 <= status < 500 for _, _, status, _ in ordered)
    for previous, current in pairwise(categories):
        row[f"transition_{previous}_to_{current}_count"] += 1
    timestamps = [observed_at for _, _, _, observed_at in ordered]
    for previous_time, current_time in pairwise(timestamps):
        row[_delay_bin_name(max(0.0, (current_time - previous_time).total_seconds()))] += 1
    row["session_duration_bucket"] = _duration_bucket(
        max(0.0, (timestamps[-1] - timestamps[0]).total_seconds())
    )
    row["automated"] = automated
    return row


def _validate_labels_and_tasks(
    labels_by_session: Mapping[str, bool], task_by_session: Mapping[str, str]
) -> None:
    if not labels_by_session:
        raise PF2ProtocolError("labels_by_session must not be empty")
    if set(labels_by_session) != set(task_by_session):
        raise PF2ProtocolError("labels_by_session and task_by_session must cover the same sessions")
    for session_id, automated in labels_by_session.items():
        if not _is_session_id(session_id) or not isinstance(automated, bool):
            raise PF2ProtocolError("labels_by_session must map opaque sessions to boolean targets")
    for task in task_by_session.values():
        if not isinstance(task, str) or not task.strip():
            raise PF2ProtocolError("task_by_session values must be non-empty audit labels")


def prepare_pf2_dataset(
    records: Iterable[Mapping[str, Any]],
    *,
    labels_by_session: Mapping[str, bool],
    task_by_session: Mapping[str, str],
    collection_window_by_session: Mapping[str, str] | None = None,
    min_sessions_per_task_class: int = 8,
) -> PF2PreparedDataset:
    """Prepare fixed-width, session-level model rows and fail closed on coverage gaps.

    The returned rows contain only target and predeclared coarse features. Opaque group
    identities and task assignment remain solely in the caller's separate split manifest.
    Exact timestamps are binned in memory and discarded.
    """

    if min_sessions_per_task_class < 1:
        raise PF2ProtocolError("min_sessions_per_task_class must be positive")
    _validate_labels_and_tasks(labels_by_session, task_by_session)
    if collection_window_by_session is not None:
        if set(collection_window_by_session) != set(labels_by_session):
            raise PF2ProtocolError(
                "collection_window_by_session must cover the same sessions as labels"
            )
        if any(
            not isinstance(window, str) or not window.strip()
            for window in collection_window_by_session.values()
        ):
            raise PF2ProtocolError(
                "collection_window_by_session values must be non-empty audit labels"
            )
    grouped: dict[str, list[tuple[str, str, int, datetime]]] = defaultdict(list)
    for record in records:
        session_id, category, method, status, observed_at = _parse_record(record)
        if session_id not in labels_by_session:
            raise PF2ProtocolError("record session_id is missing an authorized target")
        grouped[session_id].append((category, method, status, observed_at))
    if set(grouped) != set(labels_by_session):
        raise PF2ProtocolError("every labeled session must contain at least one record")
    if set(labels_by_session.values()) != {False, True}:
        raise PF2ProtocolError("corpus must contain both classes")

    coverage: dict[str, Counter[bool]] = defaultdict(Counter)
    for session_id, task in task_by_session.items():
        coverage[task][labels_by_session[session_id]] += 1
    for task, counts in coverage.items():
        if set(counts) != {False, True}:
            raise PF2ProtocolError(f"task {task!r} must contain both classes")
        if min(counts.values()) < min_sessions_per_task_class:
            raise PF2ProtocolError(
                f"task {task!r} must contain at least "
                f"{min_sessions_per_task_class} sessions per class"
            )

    window_coverage: dict[str, Counter[bool]] = defaultdict(Counter)
    if collection_window_by_session is not None:
        for session_id, window in collection_window_by_session.items():
            window_coverage[window][labels_by_session[session_id]] += 1
        for window, counts in window_coverage.items():
            if set(counts) != {False, True}:
                raise PF2ProtocolError(f"collection window {window!r} must contain both classes")

    ordered_session_ids = tuple(sorted(grouped))
    model_rows = tuple(
        _session_features(grouped[session_id], automated=labels_by_session[session_id])
        for session_id in ordered_session_ids
    )
    split_rows: tuple[dict[str, int | str], ...] = tuple(
        {
            "row_index": row_index,
            "session_id": session_id,
            "task": task_by_session[session_id],
            **(
                {"collection_window": collection_window_by_session[session_id]}
                if collection_window_by_session is not None
                else {}
            ),
        }
        for row_index, session_id in enumerate(ordered_session_ids)
    )
    feature_names = tuple(name for name in model_rows[0] if name != "automated")
    varying_feature_count = sum(
        len({row[name] for row in model_rows}) > 1 for name in feature_names
    )
    preflight_status = (
        "blocked-no-feature-variation"
        if not varying_feature_count
        else "blocked-no-task-holdout"
        if len(coverage) < 2
        else "blocked-no-temporal-holdout"
        if len(window_coverage) < 2
        else "ready-for-baseline"
    )
    preflight: dict[str, int | str] = {
        "status": preflight_status,
        "session_count": len(model_rows),
        "feature_count": len(feature_names),
        "varying_feature_count": varying_feature_count,
        "task_count": len(coverage),
        "collection_window_count": len(window_coverage),
        "automated_session_count": sum(labels_by_session.values()),
        "human_assisted_session_count": sum(not value for value in labels_by_session.values()),
    }
    return PF2PreparedDataset(
        model_rows=model_rows,
        split_rows=split_rows,
        preflight=preflight,
    )
