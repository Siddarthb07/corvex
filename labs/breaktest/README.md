# Corvex break-test lab (4–5 hosts + ART manifests)

Harder than `labs/live`: five virtual hosts, **sequential** campaigns adapted from
public Atomic Red Team / ATT&CK technique IDs, break-point scoring, and recorded video.

This is purple-team event telemetry — **no Atomic scripts or malware are vendored**.

## Attacks (manifests)

| Manifest | Hosts | Techniques | What it stresses |
|----------|-------|------------|------------------|
| `art_lateral_chain.json` | 5 | T1078, T1021, T1041 | Multi-user auth + dual egress chain (fusion required) |
| `art_cred_hop.json` | 5 | T1110, T1078, T1021, T1041 | Three distinct users chained by overlapping exfil |
| `art_slow_drip.json` | 5 | T1078, T1021, T1041 | OOD slow timing, service accounts, alt ports |
| `art_recon_pivot.json` | 4 | T1046, T1078, T1041 | Recon fan-out then auth/exfil pivot |
| `art_recon_exfil_split.json` | 4 | T1046, T1078, T1048 | Recon + split-user lateral + two egress sinks |

Easy single-user burst lateral is **not** the break-test bar. These packs force
cross-key fusion; detector-only should fragment.

## Score all manifests (no Docker)

```bash
python -m corvex build-breaktest labs/breaktest/manifests/art_lateral_chain.json \
  --out runs/breaktest/art_lateral_chain.jsonl \
  --report runs/breaktest/art_lateral_chain.breaks.json
```

Or score everything + live record:

```bash
python scripts/record_art_breaktest.py
```

Writes:

- `runs/breaktest/*.breaks.json` — correlator vs detector-only break points
- `runs/breaktest/art_manifest_summary.json`
- `docs/assets/corvex-breaktest.mp4` (+ `.gif`) — one published recording (primary ART chain)

## Live Docker (manifest-driven attacker)

```bash
# default: art_lateral_chain.json
python scripts/run_breaktest_lab.py

# or full ART suite + video
python scripts/record_art_breaktest.py
```

Attacker (`labs/breaktest/attacker/art_attack.py`) executes steps **in order**:

1. `auth` → real HTTP `/auth` on virtual hosts  
2. `exfil` / `recon` → net_conn events onto the shared bus  
3. Corvex correlates mid-chain and writes isolate flags  
4. Later hops / wave2 retries return `403`

## Adding a harder sequential attack

1. Copy a manifest under `manifests/`.
2. Use ≥4 hosts and **multiple detector keys** (different users and/or egress destinations).
3. Keep `source.repo` pointing at a public reference (e.g. Atomic Red Team).
4. Run `corvex build-breaktest … --report …` and check `fusion_lift: true` (or publish the miss).

## Honest bar

Publish break points — missed hops, over-merges, thin detector alerts — not only wins.
Live isolate in this lab is **sandbox flag-based**; `CORVEX_CONTAIN` stays off.
