# Benign corpora (dirty-replay / FP baseline)

Highest-leverage validation after synthetic fleets. **Do not hand-craft**
SCCM/RDP-shaped synthetic noise for this gate — that recreates the
“designed the test you already know how to pass” trap.

## Allowed sources

1. **Passive home-lab capture** — see `home-lab-capture/README.md`. Start Sysmon,
   do routine admin work for days/weeks, **do not inspect or curate** toward
   “traffic that will behave” until the window closes.
2. **Public captured datasets** — OTRF / Security-Datasets (Mordor) and similar.
   Prefer pure-benign slices; mixed attack+ambient is fine for adapter smoke and
   dirty-replay metrics but **cannot PASS** the gate (`corpus_kind: mixed`).

## Layout

```
labs/benign/<name>/
  README.md
  manifest.json          # corpus_kind, host_map, attack_windows, provenance
  raw/                   # gitignored captures (fetch or drop Sysmon JSON here)
  converted/             # gitignored adapter output
```

## Commands

```bash
# Fetch public OTRF smoke slice (mixed — gate stays INCOMPLETE)
python scripts/fetch_otrf_corpus.py

# Run bars (quotes pre-committed thresholds from future-plans.md)
python scripts/run_benign_baseline.py --corpus labs/benign/otrf-empire-psexec --adapter otrf
```

## Pre-committed bars (locked 2026-07-25)

| Metric | Bar |
|--------|-----|
| Minimum size | ≥ 72 host-hours, ≥ 3 hosts |
| Eligible kinds | `pure_benign`, `home_lab_capture` |
| Primary | IsolateHost FP ≤ 1 / 1000 host-hours |
| Secondary | False campaigns ≤ 1 / 100 host-hours |
| Hub | Report `hub_coverage: GAP` if no host hits hub-degree bar |

Decide PASS/FAIL against these **before** looking at the number. Do not retune
thresholds to chase a FAIL into a PASS without a new locked bar.

## Hub residual gap

Real DCs / SCCM / jump boxes are the hardest test of fix #9. If a corpus has no
hub-shaped host, the report must say `hub_coverage: GAP` — synthetic hub tests
do not count as real-data proof.
