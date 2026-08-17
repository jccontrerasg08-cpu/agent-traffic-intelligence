"""Bounded in-memory session feature aggregation."""

from __future__ import annotations

import math
import statistics
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from datetime import timedelta
from itertools import pairwise

from agent_traffic_intelligence.features.request import is_asset_path
from agent_traffic_intelligence.models import RequestEvent


@dataclass(frozen=True, slots=True)
class _Observation:
    event: RequestEvent
    is_asset: bool


class SessionFeatureState:
    """Maintain bounded per-client histories and derive behavioral features."""

    def __init__(
        self,
        *,
        max_events_per_client: int = 128,
        max_clients: int = 10_000,
        window_seconds: int = 300,
    ) -> None:
        if max_events_per_client < 2:
            raise ValueError("max_events_per_client must be at least 2")
        if max_clients < 1:
            raise ValueError("max_clients must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._max_events = max_events_per_client
        self._max_clients = max_clients
        self._window = timedelta(seconds=window_seconds)
        self._histories: OrderedDict[str, deque[_Observation]] = OrderedDict()
        self._evicted_clients = 0

    def update(self, event: RequestEvent) -> dict[str, float | int]:
        history = self._histories.pop(event.client_id, None)
        if history is None:
            if len(self._histories) >= self._max_clients:
                self._histories.popitem(last=False)
                self._evicted_clients += 1
            history = deque(maxlen=self._max_events)
        observation = _Observation(event=event, is_asset=is_asset_path(event.path))
        # ponytail: histories are capped at max_events_per_client (128 by default),
        # so sorting on each update keeps late log arrivals correct without a new index.
        ordered = sorted((*history, observation), key=lambda item: item.event.timestamp)
        cutoff = ordered[-1].event.timestamp - self._window
        history = deque(
            (item for item in ordered if item.event.timestamp >= cutoff),
            maxlen=self._max_events,
        )
        self._histories[event.client_id] = history

        return self._snapshot(history)

    def resource_metrics(self) -> dict[str, int]:
        """Return bounded-state capacity metrics for operational observability."""

        return {
            "active_client_count": len(self._histories),
            "evicted_client_count": self._evicted_clients,
            "max_client_count": self._max_clients,
        }

    @staticmethod
    def _snapshot(history: deque[_Observation]) -> dict[str, float | int]:
        events = [item.event for item in history]
        count = len(events)
        if not events:
            return {}

        first = events[0].timestamp
        last = events[-1].timestamp
        duration = max(0.0, (last - first).total_seconds())
        intervals = [
            max(0.0, (current.timestamp - previous.timestamp).total_seconds())
            for previous, current in pairwise(events)
        ]
        mean_interval = statistics.fmean(intervals) if intervals else 0.0
        if len(intervals) >= 2 and mean_interval > 0:
            interval_cv = statistics.pstdev(intervals) / mean_interval
        else:
            interval_cv = 0.0

        assets = sum(item.is_asset for item in history)
        errors = sum(event.status >= 400 for event in events)
        path_counts = Counter(event.path for event in events)
        entropy = -sum(
            (frequency / count) * math.log2(frequency / count)
            for frequency in path_counts.values()
        )

        return {
            "session_request_count": count,
            "session_duration_seconds": duration,
            "mean_interarrival_seconds": mean_interval,
            "interarrival_cv": interval_cv,
            "requests_per_minute": (count / duration * 60.0) if duration > 0 else 0.0,
            "asset_ratio": assets / count,
            "error_ratio": errors / count,
            "unique_path_ratio": len(path_counts) / count,
            "path_entropy_bits": entropy,
        }
