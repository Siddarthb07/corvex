# Contain FP scoreboard

IsolateHost and EstateLockdown figures are **proposals** from `severity.resolve_isolate_scope`. Nothing was isolated.

- Generated: `2026-11-06T09:27:01Z`
- Source: `sealed_benign`
- Packs: **6**
- Campaigns: **0**
- IsolateHost proposals: **0**
- EstateLockdown proposals: **0**
- Pure-benign estate bar: **PASS**

## Packs

| Pack | Family | Hosts | Campaigns | IsolateHost propose | EstateLockdown propose |
|------|--------|-------|-----------|---------------------|------------------------|
| `held-benign-a.jsonl` | benign | 3 | 0 | 0 | 0 |
| `held-benign-b.jsonl` | benign | 3 | 0 | 0 | 0 |
| `held-benign-c.jsonl` | benign | 3 | 0 | 0 | 0 |
| `held-benign-d.jsonl` | benign | 4 | 0 | 0 | 0 |
| `held-benign-e.jsonl` | benign | 3 | 0 | 0 | 0 |
| `held-benign-f.jsonl` | benign | 4 | 0 | 0 | 0 |

## Honesty

- Counts are resolve_isolate_scope proposals on correlator campaigns. Containment was not executed.
- CORVEX_CONTAIN was not changed. Live OS quarantine stays unimplemented.
- Scored with the in-repo default ContainPolicy (auto_enforce false). A machine-local contain_policy.json, when present, was not applied.
- first_seen/last_seen on each campaign are the min/max event timestamps for its hosts.
- On pure benign, n_estate_lockdown_propose must be 0.
- Scored unsealed held-benign-*.jsonl.sealed with the local held-out key. Plaintext stays under runs/ (gitignored).
- Train and sealed benign packs are synthetic feeder noise (egress false). They are not an enterprise benign baseline.
- This scoreboard does not set claim_allowed.
- Windows DNS-only C2 stays a sensor GAP unless Sysmon EID 22 arrives; the dashboard sensor note already says so when channel_health.dns is down.
