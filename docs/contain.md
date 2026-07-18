# Contain (dry-run only)

## Status

- **Available:** typed `ActionEnvelope` + dry-run proposer that **only logs**.
- **Not available:** live isolate / kill / firewall. `CORVEX_CONTAIN=0`.
- **Checklist:** `reports/security_l1_checklist.json` — items stay false until evidenced.

Do not flip checklist bits without evidence.

## Dry-run

```bash
corvex contain-dry-run IsolateHost --host host-a --rationale "demo"
```

Writes one line to `reports/stage_d_dry_run.jsonl`. No host mutation.

## Unlock rule

`require_contain()` passes only when every L1 key in `security_l1_checklist.json` is true **and** a real executor exists under hostile-bus tests. Today: neither.

See [`corvex/contain/CHECKLIST.md`](../corvex/contain/CHECKLIST.md).
