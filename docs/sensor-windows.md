# Windows Security → Corvex (observe-only)

One real sensor path before JetStream/mTLS: export auth logs, adapt, ingest.

## Pipeline strangers can copy

```bash
# 1. On a Windows lab box — export successful logons (Event ID 4624)
#    Event Viewer → Windows Logs → Security → Filter → Save as JSON
#    or: wevtutil qe Security /q:"*[System[(EventID=4624)]]" /f:json > export.json

# 2. Adapt → signed BYO JSONL (uses local ~/.corvex enrollment)
corvex adapt-windows path/to/export.json --out runs/sensors/windows_auth.jsonl

# 3. Ingest onto the bus the dash/correlator already understand
corvex ingest-byo runs/sensors/windows_auth.jsonl --out-bus runs/prod/events.jsonl

# 4. Monitor
corvex dash --run-dir runs/prod
```

Sample fixture: `fixtures/windows_security_sample.json`.

## What this is / isn't

| Is | Isn't |
|----|--------|
| Observe-only converter | Live Stage B sensor unlock |
| Event 4624 → `auth` envelopes | Full EVTX parser / Sysmon coverage |
| Documented stranger path | mTLS / JetStream bus |

Stage B live `SysmonJsonSensor` / JetStream stay gated. This path only proves: **OS export → JSONL → correlator**.
