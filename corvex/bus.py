"""EventBus protocol + JsonlBus + JetStreamBus stub."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional, Protocol, runtime_checkable

from corvex.envelope import EventEnvelope


@runtime_checkable
class EventBus(Protocol):
    def publish(self, envelope: EventEnvelope) -> None: ...

    def subscribe(self, cursor: Optional[str] = None) -> Iterator[EventEnvelope]: ...

    def commit(self, cursor: str) -> None: ...


@dataclass
class JsonlBus:
    """Append-only JSONL bus with durable commit cursor (file offset)."""

    path: Path
    cursor_path: Optional[Path] = None

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.cursor_path is None:
            self.cursor_path = self.path.with_suffix(self.path.suffix + ".cursor")
        if not self.path.exists():
            self.path.touch()

    def publish(self, envelope: EventEnvelope) -> None:
        line = json.dumps(envelope.to_dict(), separators=(",", ":")) + "\n"
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)

    def subscribe(self, cursor: Optional[str] = None) -> Iterator[EventEnvelope]:
        start = 0
        if cursor is None and self.cursor_path and self.cursor_path.exists():
            raw = self.cursor_path.read_text(encoding="utf-8").strip()
            if raw:
                start = int(raw)
        elif cursor:
            start = int(cursor)
        with self.path.open("r", encoding="utf-8") as fh:
            fh.seek(start)
            while True:
                pos = fh.tell()
                line = fh.readline()
                if not line:
                    break
                if not line.strip():
                    continue
                env = EventEnvelope.from_dict(json.loads(line))
                # Attach resume cursor as event_id-adjacent via iterator protocol:
                # callers commit using the byte offset after this line.
                env_cursor = str(fh.tell())
                # Yield envelope; store last offset on instance for convenience.
                self._last_offset = env_cursor  # type: ignore[attr-defined]
                self._last_read_pos = pos  # type: ignore[attr-defined]
                yield env

    def commit(self, cursor: str) -> None:
        assert self.cursor_path is not None
        self.cursor_path.write_text(str(int(cursor)), encoding="utf-8")

    def last_cursor(self) -> str:
        return getattr(self, "_last_offset", "0")


class JetStreamBus:
    """Stage B+ stub — not implemented in Stage A."""

    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "JetStreamBus is Stage B only. Stage A must use JsonlBus."
        )

    def publish(self, envelope: EventEnvelope) -> None:
        raise NotImplementedError

    def subscribe(self, cursor: Optional[str] = None) -> Iterator[EventEnvelope]:
        raise NotImplementedError
        yield  # pragma: no cover

    def commit(self, cursor: str) -> None:
        raise NotImplementedError
