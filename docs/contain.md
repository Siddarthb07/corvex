# Contain (dry-run + gated live scaffold)

## Status

- **Available:** typed `ActionEnvelope` + dry-run proposer that **only logs**.
- **Lab:** `corvex quarantine --lab-dir …` writes sandbox flags virtual hosts honor.
- **Live scaffold:** `corvex.contain.live` — requires L1 checklist 100% + `CORVEX_CONTAIN!=0` + passing `corvex hostile-bus-test`. Even then, **OS/EDR/VLAN quarantine is not implemented**; only lab flags mutate.
- **Checklist:** `reports/security_l1_checklist.json` — items stay false until evidenced.

Do not flip checklist bits without evidence.

## Dry-run

```bash
corvex contain-dry-run IsolateHost --host host-a --rationale "demo"
corvex quarantine host-a,host-b --rationale "mid-chain"
corvex quarantine-status
```

## Hostile bus (P4 evidence)

```bash
corvex hostile-bus-test
```

Writes `reports/hostile_bus_selftest.json`. Proves typed verbs, authz ≠ envelope, anti-replay, expiry fail-closed. **Does not** unlock production isolate.

## Unlock rule

Live path opens only when:

1. Every L1 key is evidenced true
2. `hostile_bus_selftest` pass
3. `CORVEX_CONTAIN!=0`
4. Separate authz token presented (`CORVEX_CONTAIN_AUTHZ`)

OS quarantine executor remains unimplemented — honest `cannot_quarantine` without `--lab-dir`.

See [`corvex/contain/CHECKLIST.md`](../corvex/contain/CHECKLIST.md).
