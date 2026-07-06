# Stage D — Contain (STARTED, NOT UNLOCKED)

## Honest status

- **Started:** typed `ActionEnvelope` + dry-run proposer that **only logs**.
- **Not unlocked:** live isolate / kill / firewall. `CFUSE_CONTAIN=0`.
- **Checklist:** `reports/security_l1_checklist.json` — **all items false** until evidenced.

Flipping checklist bits without evidence would poison the college/GitHub honesty story. Do not do it.

## How to dry-run

```bash
python -m campaignfuse.cli contain-dry-run IsolateHost --host host-a --rationale "demo"
```

Writes one line to `reports/stage_d_dry_run.jsonl`. No host mutation.

## Unlock rule

`require_contain()` passes only when every L1 key in `security_l1_checklist.json` is true **and** a real executor exists under hostile-bus tests. Today: neither.
