# Phase 0 completion — one Windows PC (2026-08-13)

Standing public claim **unchanged**:

> Research correlator — holds up against synthetic ATT&CK-shaped fleets; not yet validated against real telemetry or benign baselines.

`claim_allowed` remains **false** (still needs second physical Windows + stranger for unlock; Phase 0 does not touch those).

## Done

| Step | Evidence |
|------|----------|
| S0 preflight | `pytest` 92 passed; `runs/rw-preflight`; `corvex claim-gates` → `claim_allowed=false` |
| Sysmon | Installed Sysmon64 (v15.21) via elevated bootstrap |
| Live sensor | `runs/os-wide-live` — wevtutil source; Security/Sysmon/PowerShell hits; bookmarks advance; firewall `zero_hits` (honest) |
| wevtutil XML fix | Stock Windows has no `/f:json` — sensor now uses `/f:xml` + `parse_wevtutil_xml` |
| S4 fuse | `reports/phase0_fuse_offline_lab_replay.md` — mode `offline_lab_replay` |
| OTRF smoke | `reports/benign_baseline_otrf-empire-psexec.md` — gate **INCOMPLETE** |
| Single-host capture | `labs/benign/home-lab-2026-08-13/` window OPEN; dry-run `reports/benign_baseline_home-lab-2026-08-13.md` — **INCOMPLETE** (1 host) |
| Follow capture | `runs/home-lab-capture` (elevated `--follow`) |

## Phase 1 (parked)

- Add Mac (`sensor-macos`) + Windows VM for ≥3 hosts
- Close ≥72 host-hour window → score for S5 PASS
- Friend stranger attestation (S1) + second *physical* Windows (S2) for `claim_allowed`

## Do not

- Soften README claim language yet
- Treat OTRF or single-host dry-run as PASS
- Write `live_second_host.json` from this machine alone
