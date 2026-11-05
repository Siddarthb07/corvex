# Benign baseline report

## Pre-committed bars (locked 2026-07-25 — before this run)

| Metric | Bar |
|--------|-----|
| Minimum corpus | ≥ 72 host-hours and ≥ 3 distinct hosts |
| Eligible kinds | `pure_benign`, `home_lab_capture` only |
| Primary (IsolateHost FP) | FP_iso / H ≤ 1/1000 host-hours |
| Secondary (false campaigns) | FP_seal / H ≤ 1/100 host-hours |
| Hub coverage | Report OK if any host ≥ hub-degree bar; else **GAP** |

Mixed / attack-ambient public slices may be scored for metrics but **cannot PASS**.
Hand-crafted SCCM/RDP synthetic noise is forbidden for this gate.

**Gate:** `INCOMPLETE`
**Corpus:** `otrf-empire-psexec` (mixed)
**Host-hours (H):** 0.108395
**Hosts:** 3
**FP_iso (IsolateHost proposals):** 3 (rate=27.67655335)
**FP_seal (campaigns):** 1 (rate=9.22551778)
**hub_coverage:** `GAP`

## Reasons

- corpus_kind='mixed' is not pure_benign/home_lab_capture — dirty/mixed replay may be reported but cannot PASS the benign gate
- corpus below minimum size (host_hours=0.108395, hosts=3; need ≥72.0 host-hours and ≥3 hosts)

## Honesty

- Quarantine = dry-run IsolateHost proposals only.
- Standing claim sentence still applies unless gate is PASS:

> Research correlator — holds up against synthetic ATT&CK-shaped fleets; not yet validated against real telemetry or benign baselines.

