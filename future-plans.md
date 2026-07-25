# Corvex — future plans

Where Corvex is today: **Stage A honesty closed**; **Stage B sensor shipped**; trust hardening shipped (**council ~4.2/5 SHIP**). **lab_verified=true**; **claim_allowed=false**. Live OS quarantine still unimplemented.

## Done (trust hardening)

- Claim honesty: `lab_verified` vs `claim_allowed`; unsigned stranger advisory
- Dash: token on all routes; API-only boot; no snapshot.json leak
- `Correlator.ingest` HMAC verify; fail-closed without enrollment
- `resign_events` verify-first + `locally_stamped`
- Ed25519 stranger self-sign (`stranger-keygen`); author HMAC does not unlock claims
- `live_second_host` gate + `scripts/record_live_host_evidence.py`

## Blocks 4.5/5 (human + second PC)

1. Elevated wevtutil on a **second physical** Windows host → `reports/live_second_host.json`
2. Jack runs `corvex stranger-keygen` + `sign-stranger-attestation` (Jack holds private key)
3. `corvex claim-gates` → both gates green

## Still later

- Habit-loop PASS without author help
- JetStream / concurrency-safe bus
- OS/EDR/VLAN quarantine after L1 + larger FCR evidence

## Fleet-limits fix wave (landed)

- **Slice A:** IsolateHost gated on egress/recon evidence (narrow FP — inert lateral-only). Not general FP solved.
- **Slice B:** shape/gap hard split (sequential reuse / lim09b); same-user sleeper resume preserved.
- **Slice C:** `host_aliases` normalize at adapt; hub-degree bridge bar with dual-user handoff exception.
- Validation: per-slice `fleet-limits` + `fleet20` + holdouts; combined smoke: **fleet20 20/20 HELD**, limits **0 BROKE**. Fragile = ambiguity margin (not equal-score multi-campaign artifact).

## Host-scale ladder (bigger breaking-point suite)

| Tier | Hosts | Events/pack | Gate to enter | Notes |
|------|-------|-------------|-----------------|-------|
| **T0** | 5–6 | ≤60 | — | fleet20 / fleet-limits today |
| **T1** | **15** | ≤200 | Combined A×B×C smoke green | Remap limits shapes; `--no-decoy` for margin compare |
| **T2** | **50** | ≤1k | wall &lt;120s, RSS &lt;500MB, **and** no-decoy `fragile_rate_held ≤ T0 + 0.10` | Cleared 2026-07-25 |
| **T3** | 100–200 | ≤5k | T2 stable | Incremental fuse / time shards — optional noise floor only |

Do not jump to 200-host packs to “prove” correlator. Never summarize HELD without fragile count. Fragile uses **ambiguity margin** (matched vs unmatched competitor), not raw top−2nd among equal-score correct campaigns.

**T1 (2026-07-25, post margin fix):** no-decoy 14 HELD (**5 fragile / 9 clean**, rate **0.3571** = T0) / 1 PARTIAL / 0 BROKE. Doc: `docs/attack-fleet-limits-t1-run.md`.

**T2 (2026-07-25):** no-decoy **50 hosts**, wall **~33s**, RSS **~34MB**, fragile_rate **0.3571** = T0 → **both gates PASS**. Decoy stress fragile_rate=1.0 (not used for gate). fleet20 **20/20 HELD**. pytest **75 passed**. Doc: `docs/attack-fleet-limits-t2-run.md`.

## Priority after council (real-attack hold) — 2026-07-25

Ordered by what to act on next (synthetic T3 **paused** until #1 has a corpus):

1. **Real / realistic benign baseline** (highest) — even a small replay of enterprise-like RDP/SCCM/admin-scan noise via BYO JSONL. Until this exists, hub-degree / contain-gate / hard-split were tuned against an unvalidated noise model. Do not invest further in T3 host-scale fleets first.
2. **Trust P0s (code)** — 1:1 producer↔host by default; fail-closed `CORVEX_CONTAIN_AUTHZ` (no hardcoded dual-control token). Landed.
3. **Evasion-doc publication** — explicit decision: keep `docs/attack-fleet-limits*.md` **public** for early-stage falsifiability; revisit before networked bus/live contain. See honesty section in `docs/attack-fleet-limits.md`.
4. **Standing public-claim rule** (below) — same authenticity pattern as Anima / VidhiSetu.

### Standing public-claim rule

Until a real/realistic **benign baseline** exists and FP / fragile behavior on it is measured, nothing about Corvex is described publicly (LinkedIn, portfolio, applications, README hero copy) as more than:

> Research correlator — holds up against synthetic ATT&CK-shaped fleets; not yet validated against real telemetry or benign baselines.

No “works on real attacks,” no commercial parity, no soft upgrades of that sentence.

## What not to do

- Mint Ed25519 as author and pretend Jack held the key
- Write `live_second_host.json` from Docker / fixture / offline_lab_replay
- Set `claim_allowed` by hand
- Fake live OS quarantine
- Cite Slice A contain gate as “FP problem solved”
- Inflate `resume_window` to days (worsens sequential-reuse)
- Build T3 fleets before a benign-baseline corpus exists
- Imply real-attack readiness from fleet20 / T0–T2 HELD counts
- Use multi-host producers or default contain authz tokens outside explicit lab opt-in
