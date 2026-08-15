"""Bounded process-local nonce replay tracking for signed requests."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field


@dataclass(slots=True)
class ReplayCache:
    max_entries: int = 4096
    _entries: OrderedDict[tuple[str, str], int] = field(default_factory=OrderedDict, init=False)

    def __post_init__(self) -> None:
        if self.max_entries < 1:
            raise ValueError("max_entries must be positive")

    def seen_or_add(self, key_id: str, nonce: str, *, expires: int, now: int) -> bool:
        self._purge(now)
        token = (key_id, nonce)
        previous_expiry = self._entries.get(token)
        if previous_expiry is not None and previous_expiry > now:
            self._entries.move_to_end(token)
            return True
        self._entries[token] = expires
        self._entries.move_to_end(token)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
        return False

    def _purge(self, now: int) -> None:
        expired = [token for token, expires in self._entries.items() if expires <= now]
        for token in expired:
            self._entries.pop(token, None)
