# Attack fleet 10 — full-intensity black-box report

Purple-team **event sketches** only. Sources cite [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) technique IDs where marked `github_art`. No malware executed. Quarantine = dry-run proposals.

- Attacks: **10** | Intensity rounds/attack: **3**
- Wall: **36.164s**
- HELD: **7** | PARTIAL: **2** | BROKE: **1**

## Fleet scoreboard

| # | Campaign | Origin | Verdict | Jaccard | Missed | Over-merged | Saved | False Q |
|---|----------|--------|---------|---------|--------|-------------|-------|---------|
| 1 | fleet01-art-cred-dump-pth | github_art | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 2 | fleet02-art-powershell-chain | github_art | **HELD** | 1.0 | - | - | host-c, host-e | - |
| 3 | fleet03-art-smb-admin-shares | github_art | **PARTIAL** | 0.5 | host-a, host-b | - | host-e | - |
| 4 | fleet04-art-recon-exfil | github_art | **HELD** | 1.0 | - | - | host-a, host-d, host-e | - |
| 5 | fleet05-art-dns-c2-only | github_art | **BROKE** | 0.0 | host-a, host-b, host-c | - | host-d, host-e | - |
| 6 | fleet06-art-password-spray | github_art | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 7 | fleet07-orig-ip-src-lateral | original | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 8 | fleet08-orig-chunked-cdn-bait | original | **HELD** | 1.0 | - | - | host-c, host-d, host-e | - |
| 9 | fleet09-orig-window-gap | original | **PARTIAL** | 0.6667 | - | - | host-d, host-e | - |
| 10 | fleet10-orig-ransom-fanout-bury | original | **HELD** | 1.0 | - | - | host-d, host-e | - |

## Where it broke

- **fleet03-art-smb-admin-shares** (github_art, PARTIAL): missed=['host-a', 'host-b'] over_merged=[] — Walk admin$ / C$ style remoting across the segment as fast as auth allows.
- **fleet05-art-dns-c2-only** (github_art, BROKE): missed=['host-a', 'host-b', 'host-c'] over_merged=[] — Beacon and exfil exclusively over DNS. Avoid classic ports.
- **fleet09-orig-window-gap** (original, PARTIAL): missed=[] over_merged=[] — Hit hard, go quiet past ten minutes, finish the job on the same hosts.

## Per-attack detail

### fleet01-art-cred-dump-pth

- Origin: `github_art` | Techniques: T1003.001, T1550.002, T1021, T1041
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -

### fleet02-art-powershell-chain

- Origin: `github_art` | Techniques: T1059.001, T1078, T1041
- Truth: host-a, host-b, host-d
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-d
- Saved: host-c, host-e | False Q: -

### fleet03-art-smb-admin-shares

- Origin: `github_art` | Techniques: T1021.002, T1078, T1041
- Truth: host-a, host-b, host-c, host-d
- Verdict: **PARTIAL** | Jaccard=0.5 | fusion_lift=False
- Quarantine dry-run: host-c, host-d
- Saved: host-e | False Q: -

### fleet04-art-recon-exfil

- Origin: `github_art` | Techniques: T1046, T1048, T1078
- Truth: host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-b, host-c
- Saved: host-a, host-d, host-e | False Q: -

### fleet05-art-dns-c2-only

- Origin: `github_art` | Techniques: T1071.004, T1078
- Truth: host-a, host-b, host-c
- Verdict: **BROKE** | Jaccard=0.0 | fusion_lift=False
- Quarantine dry-run: -
- Saved: host-d, host-e | False Q: -

### fleet06-art-password-spray

- Origin: `github_art` | Techniques: T1110.003, T1078, T1041
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -

### fleet07-orig-ip-src-lateral

- Origin: `original` | Techniques: T1021, T1078, T1041
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -

### fleet08-orig-chunked-cdn-bait

- Origin: `original` | Techniques: T1041, T1105, T1078
- Truth: host-a, host-b
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b
- Saved: host-c, host-d, host-e | False Q: -

### fleet09-orig-window-gap

- Origin: `original` | Techniques: T1078, T1041
- Truth: host-a, host-b, host-c
- Verdict: **PARTIAL** | Jaccard=0.6667 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -

### fleet10-orig-ransom-fanout-bury

- Origin: `original` | Techniques: T1486, T1078, T1041
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -

## Honesty

- Black-box narratives; scoring uses Corvex break-point machinery.
- DNS-only and window-gap packs are intentional stress cases.
- Live OS quarantine remains unimplemented.
