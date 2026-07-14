# Contain (dry-run only)

## Honest status

- **Available:** typed `ActionEnvelope` + dry-run proposer that **only logs**.
- **Not available:** live isolate / kill / firewall. `CFUSE_CONTAIN=0`.
- **Checklist:** `reports/security_l1_checklist.json` — items stay false until evidenced.

Do not flip checklist bits without evidence.

## How to dry-run

```bash
python -m campaignfuse.cli contain-dry-run IsolateHost --host host-a --rationale "demo"
```

Writes one line to `reports/stage_d_dry_run.jsonl`. No host mutation.

## Unlock rule

`require_contain()` passes only when every L1 key in `security_l1_checklist.json` is true **and** a real executor exists under hostile-bus tests. Today: neither.

See [`campaignfuse/contain/CHECKLIST.md`](../campaignfuse/contain/CHECKLIST.md).
