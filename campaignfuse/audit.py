"""Hash-chained append-only audit of campaign decisions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")
        self._tip = self._read_tip()

    def _read_tip(self) -> str:
        tip = "0" * 64
        if not self.path.exists():
            return tip
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            tip = json.loads(line)["entry_hash"]
        return tip

    def append(self, kind: str, payload: Mapping[str, Any]) -> str:
        body = {
            "prev": self._tip,
            "kind": kind,
            "payload": dict(payload),
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        entry_hash = hashlib.sha256(canonical).hexdigest()
        record = {**body, "entry_hash": entry_hash}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
        self._tip = entry_hash
        return entry_hash

    @property
    def tip(self) -> str:
        return self._tip

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec["prev"] != prev:
                return False
            body = {"prev": rec["prev"], "kind": rec["kind"], "payload": rec["payload"]}
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if hashlib.sha256(canonical).hexdigest() != rec["entry_hash"]:
                return False
            prev = rec["entry_hash"]
        return True
