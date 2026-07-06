# Corvex Threat Model (Day 0 / L0)

Scope: Stage A bake-off operator + BYO-JSONL experimenter. No remote sensors. No actuators.

## Assets

| Asset | Sensitivity |
|-------|-------------|
| Held-out packs + ground truth | Critical — sealed; unlock key outside repo |
| Scorer / Campaign-F1 rules | Critical — hashed inside sealed bundle |
| Per-producer HMAC secrets | High — never commit defaults |
| Campaign decisions / audit chain | High — append-only hash chain |
| Train packs | Low — public for bake-off |

## Actors

1. **Bake-off operator (author)** — trusted to run sealed eval once; peek at held-out key = conscious cheat.
2. **BYO-JSONL experimenter** — supplies envelopes; must enroll producers.
3. **Adversarial pack author** — may craft events to inflate F1; countered by sealed held-out + B2 parity.
4. **Supply-chain / CI attacker** — may try to commit shared HMAC secrets or actuator code.

## Trust boundaries

```
[Feeder / BYO] --HMAC--> [EventBus] --> [Detectors] --> [Correlator] --> [CampaignStore]
                                              \--> [B1/B2] ------------^
[Held-out ciphertext] --key outside repo--> [Eval only]
```

- Correlator paths **cannot** decrypt held-out.
- Eval package **must not** import correlator internals.
- Actuator executors absent from installable package through Stage C.

## Threats & controls (L0)

| ID | Threat | Control |
|----|--------|---------|
| T1 | Tuning on held-out | Age ciphertext + external key + published SEALED.sha256 before correlator work |
| T2 | Shared/default HMAC | CI fails if default secret committed; per-producer secrets Day 0 |
| T3 | Host spoof / unbound host | Enrollment map; host_id inside HMAC |
| T4 | Replay | nonce + event_id dedup table before campaign mutate |
| T5 | Soft PASS criteria | Pre-registered automated gate only |
| T6 | Actuator in wheel | drafts/actions not installed; import-linter + abuse tests |
| T7 | Eval peeking correlator | import-linter forbidden contract |

## Out of scope (L0)

Remote publish, mTLS, Contain/actuators, operator narrative rubric as gate.
