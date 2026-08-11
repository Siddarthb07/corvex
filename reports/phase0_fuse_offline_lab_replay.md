# Phase 0 fuse evidence (offline_lab_replay)

**Date:** 2026-08-13  
**Mode:** `offline_lab_replay` — file merge + correlator; **not** JetStream / not concurrent product bus.

## Sources

| Source | Path |
|--------|------|
| Lab | `labs/breaktest/shared/events.jsonl` (art_lateral_chain, 8 events) |
| PC | `runs/os-wide-live` (live wevtutil sensor on this Windows PC) |
| Out | `runs/pc-and-lab` |

## Result

- `lines_appended`: 59 (58 envelopes after skip)
- Campaigns: 2 (lab lateral packs)
- `hmac_rejected`: 0
- Dashboard: `reports/dashboard/index.html` (`corvex dash --run-dir runs/pc-and-lab --build`)

## Honesty

This proves lab JSONL + live PC envelopes merge under one enrollment. It is **not** real-world multi-host campaign validation and does **not** unlock `claim_allowed`.
