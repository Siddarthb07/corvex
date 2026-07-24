"""Stage B sensors — gated behind Stage A PASS + stranger dry-run."""

from corvex.sensors.file_tail import tail_jsonl
from corvex.sensors.jetstream_mtls import JetStreamMTLSConfig, connect_jetstream
from corvex.sensors.windows_os import run_sensor_windows

__all__ = [
    "tail_jsonl",
    "JetStreamMTLSConfig",
    "connect_jetstream",
    "run_sensor_windows",
]
