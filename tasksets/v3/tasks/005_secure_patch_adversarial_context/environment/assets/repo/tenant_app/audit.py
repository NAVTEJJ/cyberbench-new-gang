from __future__ import annotations


class AuditLog:
    """Append-only in-memory audit sink used by the benchmark service."""

    def __init__(self):
        self._events = []

    def record(self, event: str, **fields) -> None:
        safe = {k: v for k, v in fields.items() if "secret" not in k.lower() and "signature" not in k.lower()}
        self._events.append({"event": event, **safe})

    @property
    def events(self) -> list[dict]:
        return [dict(x) for x in self._events]
