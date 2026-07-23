# Changelog

## [1.0.1] — 2026-07-23

### Removed
- Pitch / demo GIFs and MP4s from `docs/assets/` (30s pitch, live lab, attack theatre, break-test recordings). Run labs locally if you want recordings; they are not shipped in the tree.

### Added
- ART-style **break-test lab** (`labs/breaktest/`): 4–5 host Docker topology, sequential manifests (`art_lateral_chain`, `art_cred_hop`, `art_slow_drip`, `art_recon_pivot`, `art_recon_exfil_split`), manifest-driven attacker.
- `corvex build-breaktest` + `corvex.eval.break_points` — correlator vs detector-only diagnostics (`fusion_lift`, thin alerts, missed/over-merged hosts).
- `fusion_chain` pack family + `train/train-fusion-chain.jsonl`; `seal-day0` registers 5-host fusion held-out specs.
- Windows Security auth export adapter: `corvex adapt-windows`, `docs/sensor-windows.md`, sample fixture.
- `future-plans.md` — next moves and honesty gates.

### Changed
- Detector-only ablation groups **per alert key** (user / dst / host) without cross-key merge — honest fusion gap.
- Correlator cluster merge is **transitive** (full hop chains fuse).
- Live defender ingests `net_conn` (exfil/recon) as well as auth; supports `CORVEX_LAB_HOSTS` for 5-host labs.
- Lab enrollment merges missing demo hosts (e.g. `host-e`) without wiping secrets.
- README demos section removed; docs point at break-test + quick start instead.

### Safety / limits (unchanged)
- Live contain stays locked (`CORVEX_CONTAIN=0`). Lab isolate is sandbox flag-based.
- Sealed metrics remain synthetic until re-seal + held-out eval publish. Not a claim of real-world malware defense or commercial-tool parity.

## [0.4.0] — prior

Observe/correlate correlator, sealed synthetic eval narrative, live Docker lab, dashboard, gated Stage B stubs.
