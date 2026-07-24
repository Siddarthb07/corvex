# Changelog

## [Unreleased]

### Added
- Stage B OS-wide Windows sensor: `corvex sensor-windows` (Security + Sysmon + Firewall + PowerShell), fixtures under `fixtures/os_wide/`, `docs/os-wide-sensor.md`, multi-host smoke script, `corvex habit-loop`.

## [1.1.0] — 2026-07-23

### Added
- P1: expanded sealed benign N=5; `corvex eval-recon` reconstruction→manifest regression.
- P2: `corvex byo-windows` / `correlate-byo`; `--host-map` on `adapt-windows`; stranger checklist.
- P3: `corvex claim-gates` + `score-non-author` (claim_allowed locked until stranger attestation).
- P4: `corvex.contain.live` + `hostile-bus-test` (OS quarantine still unimplemented; lab flags only).

### Changed
- Held-out now separates correlator F1 **1.00** from detector-only **0.67** (fusion_chain).
- `seal-day0 --force` clears held-out as well as train.
- Published RESULTS / README metrics refreshed after re-seal.

### Safety
- Live contain still gated; `CORVEX_CONTAIN=0` default. Hostile-bus pass ≠ OS isolate unlocked.

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
