"""CampaignStore — JSONL per run, single writer, schema_version."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA_VERSION = 1


@dataclass
class Campaign:
    campaign_id: str
    host_ids: List[str]
    stages: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    score: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Campaign":
        return cls(
            campaign_id=str(data["campaign_id"]),
            host_ids=list(data["host_ids"]),
            stages=list(data.get("stages", [])),
            evidence=list(data.get("evidence", [])),
            score=float(data.get("score", 1.0)),
        )


class CampaignStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._campaigns: Dict[str, Campaign] = {}
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("type") == "meta":
                continue
            c = Campaign.from_dict(rec["campaign"])
            self._campaigns[c.campaign_id] = c

    def upsert(self, campaign: Campaign) -> None:
        self._campaigns[campaign.campaign_id] = campaign
        self._rewrite()

    def _rewrite(self) -> None:
        lines = [
            json.dumps({"type": "meta", "schema_version": SCHEMA_VERSION}, separators=(",", ":"))
        ]
        for c in self._campaigns.values():
            lines.append(
                json.dumps({"type": "campaign", "campaign": c.to_dict()}, separators=(",", ":"))
            )
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def all(self) -> List[Campaign]:
        return list(self._campaigns.values())

    def get(self, campaign_id: str) -> Optional[Campaign]:
        return self._campaigns.get(campaign_id)
