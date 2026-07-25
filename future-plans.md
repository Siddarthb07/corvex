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

1. **Real / realistic benign baseline** (highest) — see **Benign corpus plan** below. Not hand-crafted SCCM/RDP noise.
2. **Trust P0s (code)** — 1:1 producer↔host by default; fail-closed `CORVEX_CONTAIN_AUTHZ` (no hardcoded dual-control token). Landed.
3. **Evasion-doc publication** — keep `docs/attack-fleet-limits*.md` **public** for early-stage falsifiability; revisit before networked bus/live contain.
4. **Standing public-claim rule** (below).

### Standing public-claim rule

Until a real/realistic **benign baseline** exists and FP / fragile behavior on it is measured, nothing about Corvex is described publicly (LinkedIn, portfolio, applications, README hero copy) as more than:

> Research correlator — holds up against synthetic ATT&CK-shaped fleets; not yet validated against real telemetry or benign baselines.

No “works on real attacks,” no commercial parity, no soft upgrades of that sentence.

---

## Benign corpus plan (next build) — scoped 2026-07-25

This is the highest-leverage remaining work. Scope is locked **before** capture/adapter work so results stay falsifiable (same spirit as keeping the evasion docs public).

### Anti-pattern (do not do this)

Do **not** hand-craft SCCM-shaped / RDP-shaped / admin-scan synthetic noise from beliefs about “what real admin traffic looks like.” That is the same trap that made fleet20’s original 20/20 suspicious — designing the test you already know how to pass. Fix-wave A/B/C were tuned against synthetic decoys; inventing more synthetic “benign” in that same dialect does not validate them.

### Allowed corpus sources (prefer in this order)

1. **Passive home-lab capture** — Sysmon (and whatever else the existing adapter accepts) from a lab running routine admin work over **days/weeks**. Protocol: start capture → do normal work → **do not inspect or curate the stream toward “traffic that will behave”** until the collection window closes. Only then convert to Corvex JSONL.
2. **Public captured datasets** — e.g. [OTRF / Security Datasets (Mordor)](https://github.com/OTRF/Security-Datasets) host Sysmon JSON where a **benign-labeled** or attack-excluded slice exists. Prefer datasets you did not author. Document provenance + license in the corpus README.
3. **Forbidden for this gate:** regenerating “enterprise-like” noise with the fleet-limits generators, or editing captured events to look quieter.

Mixed attack+benign Mordor sets are fine for dirty-replay **only if** attack windows are labeled and excluded from the pure-benign FP score (or scored separately as detection, not as FP).

### Pre-committed success / failure bars (set before first run)

Do not decide after seeing the number. First pure-benign replay that meets the minimum size below is scored against these bars; the report must quote them verbatim.

**Minimum corpus size before the gate counts**

- ≥ **72 host-hours** of pure-benign telemetry (e.g. 3 hosts × 24h, or 1 host × 72h), **or** a public dataset slice of comparable density with documented host-hour estimate.
- At least **3 distinct hosts** in the enrollment (single-host-only corpora can still be reported, but cannot alone PASS the gate).

**Primary bar — false IsolateHost proposals (contain dry-run)**

- Let `FP_iso` = number of `IsolateHost` proposals emitted on the pure-benign corpus.
- Let `H` = measured host-hours.
- **PASS** if `FP_iso / H ≤ 1/1000` (≤ one false IsolateHost proposal per 1000 host-hours).
- **FAIL** if `FP_iso / H > 1/1000`.
- Rationale: attack fleets currently show high precision on synthetic campaigns; a benign FP rate more than ~orders-of-magnitude above “almost never” on quiet admin traffic means the correlator is not safe to describe as anything beyond synthetic-fleet research. Absolute rate beats “Nx attack precision” because lab precision ≈ 1.0 and is not a useful denominator.

**Secondary bar — false sealed campaigns**

- Let `FP_seal` = sealed campaigns whose host set is entirely from the benign corpus with no labeled attack window.
- **PASS** if `FP_seal / H ≤ 1/100` (≤ one false seal per 100 host-hours).
- **FAIL** if higher.
- Sealed-but-not-proposed-contain is still a real FP for the product claim; it just sits below IsolateHost severity.

**Tertiary — fragile / margin (informational, not gate)**

- Report fragile_rate and ambiguity margins on any campaigns that do open. Do **not** retune thresholds to make these look good before the primary/secondary bars are met.

### Hub-degree residual gap (must note, not assume)

Fix #9 (hub-degree bar) is the piece most likely to break on real data. Real environments have genuine high-degree legitimate hosts (DCs, SCCM, jump boxes); synthetic decoys only approximated them.

On every benign-corpus run, the report **must** include:

1. Per-host peer-degree / alias fan-out stats under the same metrics the correlator uses for hub exclusion.
2. Whether **any** host meets or exceeds the configured hub-degree bar on pure-benign traffic.
3. If **no** hub-shaped host appears: mark **`hub_coverage: GAP`** — synthetic hub tests remain unvalidated by this corpus; do **not** claim #9 is real-data-proven. Prefer extending capture (add a jump box / management host role) or picking a public set that includes such roles before calling the benign gate complete.

### Deliverables for this build

1. Corpus under something like `labs/benign/<name>/` with provenance README (source, dates, host roles, license, capture protocol).
2. Adapter path: raw Sysmon/Security-Datasets → Corvex JSONL (reuse existing adapters where possible; no silent event drops without logging counts).
3. Runner: `scripts/run_benign_baseline.py` (or equivalent) that prints `FP_iso`, `FP_seal`, `H`, pass/fail vs the bars above, and `hub_coverage`.
4. Report under `reports/` quoting the pre-committed bars and the outcome. Claim sentence stays until both primary and secondary PASS (and hub GAP is either closed or explicitly residual).

### Build status (started 2026-07-25)

Landed:
- `corvex/adapters/otrf.py` — Mordor/OTRF → os_wide envelopes (firewall ID remap, flat EventData).
- `corvex/eval/benign_baseline.py` — locked bars + hub_coverage helper.
- `scripts/fetch_otrf_corpus.py` / `scripts/run_benign_baseline.py`.
- `labs/benign/` layout + home-lab capture protocol.
- Tests: `tests/test_benign_baseline.py`.
- Smoke corpus: OTRF `empire_psexec_dcerpc_tcp_svcctl` (`corpus_kind: mixed`) — adapter validation only; gate **INCOMPLETE** by design.

Still needed for a gate-eligible run:
- Passive home-lab capture (≥72 host-hours, ≥3 hosts) **or** a public pure-benign slice.
- Prefer a capture that includes a hub-shaped role so `hub_coverage` is not GAP.

### What this build does *not* include

- T3 fleets
- Retuning hub / contain / hard-split gates to chase a FAIL into a PASS without a written rationale and a new pre-committed bar
- Hand-authored “looks like SCCM” JSONL

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
- Hand-craft benign noise shaped to pass the correlator
- Decide FP success/failure after seeing the number
- Treat synthetic hub tests as sufficient when the benign corpus has no hub-shaped hosts
