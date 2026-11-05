# Claim gates — machine-checked field language

Corvex separates **lab scores** from **public claims**. The mechanism is
`corvex claim-gates` → [`corvex/eval/claim_gates.py`](../corvex/eval/claim_gates.py)
writing [`reports/claim_gates.json`](../reports/claim_gates.json).

## Two bits (never conflate)

| Bit | Meaning | Flipped by |
|-----|---------|------------|
| `lab_verified` | Sealed held-out + breaktest fusion lift + trust probes look coherent | Eval / probes |
| `claim_allowed` | Permission to say more than the standing synthetic-fleet sentence | **All five gates pass** |

Standing public sentence until `claim_allowed=true`:

> Research correlator — holds up against synthetic ATT&CK-shaped fleets; not validated against real telemetry or benign baselines.

## Gate checklist (all required)

| Gate | Evidence file / probe | What it blocks |
|------|----------------------|----------------|
| `non_author_fusion_lift` | `reports/non_author_fusion.json` | Publishing fusion as useful when detector-only is as good |
| `stranger_success` | `reports/stranger_dry_run.json` + Ed25519 | Author-only “outsider” attestations; agent dry-runs; author HMAC |
| `benign_fcr_real_n` | sealed held-out benign metrics | Claiming low FP without ≥N benign packs |
| `trust_integrity` | in-process probes | Dash snapshot bypass, unsigned ingest, resign without verify |
| `live_second_host` | `reports/live_second_host.json` (`source=wevtutil`) | Single-machine “fleet” stories |

Demo of a blocked overclaim:

```bash
python scripts/demo_blocked_claim.py
```

## What the lock is (and is not)

**Is:** a reproducible check that refuses to set `claim_allowed=true` unless
artifacts on disk pass fixed predicates. `stage-b-lab-unlock` writes a lab
override for sensors only — the claim evaluator ignores it for `claim_allowed`.

**Is not:** a cryptographic DRM or remote attestation of the author's laptop.
A determined author can edit JSON by hand or delete the check. The point is
**discipline and auditability for the paper / README / portfolio**: any claim
sentence must match a freshly generated `claim_gates.json`. Reviewers can re-run
`corvex claim-gates` after clone.

### Tamper model (honest)

| Attack | Mitigated? |
|--------|------------|
| Soften README while gate fails | Process / review — gate file still shows false |
| Author HMAC stranger attestation | Rejected (`stranger_signature_ok` requires Ed25519 stranger custody) |
| `CORVEX_STAGE_B=1` env unlock | Removed |
| Hand-edit `claim_allowed` in JSON | Possible — not prevented; detected if CI re-runs evaluator |
| Invent `live_second_host.json` from fixtures | Script checks `source=wevtutil` + non-empty events; still forgeable offline |

## Concrete blocked claim (this tree)

As of the latest gate run, `claim_allowed=false` solely because
`live_second_host` is missing. Lab scores may be strong; the public sentence
does not upgrade.

## Related

- Operator sequence: [`docs/real-world-test-sequences.md`](real-world-test-sequences.md)
- Second host: [`docs/s2-second-host.md`](s2-second-host.md)
- Stranger: [`docs/stranger-checklist.md`](stranger-checklist.md)
