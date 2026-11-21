"""Simple synchronous event bus for scan lifecycle notifications."""
from __future__ import annotations
from collections import defaultdict
from typing import Any, Callable

Handler = Callable[..., None]

class EventBus:
    def __init__(self):
        self._handlers: dict[str, list[Handler]] = defaultdict(list)

    def on(self, event: str, handler: Handler) -> None:
        self._handlers[event].append(handler)

    def off(self, event: str, handler: Handler) -> None:
        if handler in self._handlers.get(event, []):
            self._handlers[event].remove(handler)

    def emit(self, event: str, **payload: Any) -> None:
        for handler in list(self._handlers.get(event, [])):
            try:
                handler(**payload)
            except Exception:
                # A broken listener must not break the scan.
                pass

    def clear(self) -> None:
        self._handlers.clear()
