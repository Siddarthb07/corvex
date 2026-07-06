"""NATS JetStream + mTLS scaffolding (Stage B). Not used in Stage A."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from campaignfuse.stage_b import JetStreamBus, habit_loop_metric, require_stage_b


@dataclass
class JetStreamMTLSConfig:
    servers: str
    client_cert: str
    client_key: str
    ca_cert: str
    stream: str = "cfuse-events"
    subject: str = "cfuse.events.>"


def connect_jetstream(config: JetStreamMTLSConfig) -> JetStreamBus:
    """Requires Stage B unlock + mTLS material. Stage A must not call this."""
    require_stage_b()
    bus = JetStreamBus(
        config.servers,
        subject=config.subject,
        ca_cert=Path(config.ca_cert),
        client_cert=Path(config.client_cert),
        client_key=Path(config.client_key),
    )
    return bus


def habit_loop_metric_doc() -> str:
    return habit_loop_metric(False)["definition"]
