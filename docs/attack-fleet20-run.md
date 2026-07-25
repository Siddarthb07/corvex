# Attack fleet 20 — run details

Purple-team **event sketches** only. Sources cite [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) technique IDs where marked `github_art`. No malware executed. Quarantine = dry-run IsolateHost proposals only (live OS quarantine is not implemented).

## Run overview

| | |
|--|--|
| Suite | Attack fleet **20** (black-box) |
| Command | `python scripts/run_attack_fleet10.py 2` |
| Intensity | **2** rounds per attack (`build-breaktest` + `replay` each) |
| Wall time | **~47s** (last recorded run) |
| Result | **20 HELD / 0 PARTIAL / 0 BROKE** |
| Reports | `reports/attack_fleet20.md`, `reports/attack_fleet20.json` |
| Manifests | `labs/breaktest/manifests/fleet20/` |

Also: unit suite `pytest tests/` — **66** passed on the same wave.

## Column meanings

| Column | Meaning |
|--------|---------|
| **Jaccard** | Best correlator campaign vs truth hosts (`1.0` = exact match) |
| **Saved** | Innocent hosts not falsely proposed for dry-run quarantine |
| **False Q** | Innocents that *were* proposed (dry-run only) |
| **Missed / Over-merged** | Relative to the **best-matching** campaign (not the union of all campaigns) |
| **Verdict** | `HELD` = matched truth, no best-campaign over-merge; `PARTIAL` / `BROKE` otherwise |

## Scoreboard

| # | Attack | Origin | Techniques | Truth | Q dry-run | Saved | False Q |
|---|--------|--------|------------|-------|-----------|-------|---------|
| 1 | Cred dump → PtH | GitHub ART | T1003.001, T1550.002, T1021, T1041 | a,b,c | a,b,c | d,e | — |
| 2 | PowerShell chain | GitHub ART | T1059.001, T1078, T1041 | a,b,d | a,b,d | c,e | — |
| 3 | SMB admin$ hops | GitHub ART | T1021.002, T1078, T1041 | a,b,c,d | a,b,c,d | e | — |
| 4 | Recon → exfil | GitHub ART | T1046, T1048, T1078 | b,c | b,c | a,d,e | — |
| 5 | DNS C2 only | GitHub ART | T1071.004, T1078 | a,b,c | a,b,c | d,e | — |
| 6 | Password spray | GitHub ART | T1110.003, T1078, T1041 | a,b,c | a,b,c | d,e | — |
| 7 | IP-only src lateral | Original | T1021, T1078, T1041 | a,b,c | a,b,c | d,e | — |
| 8 | Chunked exfil + CDN bait | Original | T1041, T1105, T1078 | a,b | a,b | c,d,e | — |
| 9 | Window-gap sleeper | Original | T1078, T1041 | a,b,c | a,b,c | d,e | — |
| 10 | Ransom fanout + buried op | Original | T1486, T1078, T1041 | a,b,c | a,b,c | d,e | — |
| 11 | Scheduled task | GitHub ART | T1053.005, T1078, T1041 | a,b,c | a,b,c | d,e | — |
| 12 | WMI remote | GitHub ART | T1047, T1021, T1041 | a,b,d | a,b,d | c,e | — |
| 13 | Cloud cred egress | GitHub ART | T1552.005, T1078, T1041 | b,c | b,c | a,d,e | — |
| 14 | RDP hop | GitHub ART | T1021.001, T1078, T1041 | a,c,e | a,c,e | b,d | — |
| 15 | Mail collect | GitHub ART | T1114, T1078, T1041 | a,b | a,b | c,d,e | — |
| 16 | Dual-user bridge | Original | T1078, T1041 | a,b,c | a,b,c | d,e | — |
| 17 | DNS + lateral | Original | T1071.004, T1078, T1041 | a,b,c | a,b,c | d,e | — |
| 18 | Burst retries | Original | T1110, T1078, T1041 | a,b,c | a,b,c | d,e | — |
| 19 | Helpdesk vs APT | Original | T1078, T1041 | a,b,c | APT + helpdesk | e | **d** |
| 20 | CDN + APT | Original | T1105, T1078, T1041 | a,b,c | a,b,c | d,e | — |

All 20 in the recorded run: **verdict HELD**, **Jaccard 1.0**, no missed / over-merged on the best campaign.

## Note on attack #19 (helpdesk vs APT)

APT matched perfectly. Helpdesk still forms a **separate** `{c,d}` lateral campaign, so dry-run also proposes **host-d** (False Q). That is intentional anti-jumpbox behavior (two laterals stay split), not an APT over-merge into one fat campaign.

## How a single attack is scored

1. Adapt fleet manifest → signed pack  
2. `corvex build-breaktest` → correlator vs detector-only break points  
3. `corvex replay` → reconstruction + quarantine dry-run  
4. Repeat for intensity rounds; last round is what the scoreboard reports  

## Fixes that made prior breaks hold

| Prior break | Cause | Fix |
|-------------|--------|-----|
| DNS-only C2 | No DNS stitch key | `dns_beacon` on shared DNS apex |
| SMB 4-hop miss | Hop user poisoned as shared-svc | High-fanout keeps **host-\*** hop chains only |
| Window gap | Quiet pause >600s | `resume_window_seconds=3600` same-user resume |
| Helpdesk hitch | Lateral glued via jump+exfil | Refuse merging **two lateral** campaigns on one host |

## Re-run

```bash
python scripts/run_attack_fleet10.py 2
# optional: more intensity rounds
python scripts/run_attack_fleet10.py 3

pytest tests/ -q
```

Full machine-readable dump: `reports/attack_fleet20.json`.  
Short scoreboard refresh: `reports/attack_fleet20.md`.
