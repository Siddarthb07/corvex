# Attack fleet 20 — full-intensity black-box benchmark

Purple-team **event sketches** only. Sources cite [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) technique IDs where marked `github_art`. No malware executed. Quarantine = dry-run proposals.

- Attacks: **20** | Intensity rounds/attack: **2**
- Wall: **41.6308s**
- HELD: **20** | PARTIAL: **0** | BROKE: **0**

## Fleet scoreboard

| # | Campaign | Origin | Verdict | Jaccard | Missed | Over-merged | Saved | False Q |
|---|----------|--------|---------|---------|--------|-------------|-------|---------|
| 1 | fleet01-art-cred-dump-pth | github_art | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 2 | fleet02-art-powershell-chain | github_art | **HELD** | 1.0 | - | - | host-c, host-e | - |
| 3 | fleet03-art-smb-admin-shares | github_art | **HELD** | 1.0 | - | - | host-e | - |
| 4 | fleet04-art-recon-exfil | github_art | **HELD** | 1.0 | - | - | host-a, host-d, host-e | - |
| 5 | fleet05-art-dns-c2-only | github_art | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 6 | fleet06-art-password-spray | github_art | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 7 | fleet07-orig-ip-src-lateral | original | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 8 | fleet08-orig-chunked-cdn-bait | original | **HELD** | 1.0 | - | - | host-c, host-d, host-e | - |
| 9 | fleet09-orig-window-gap | original | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 10 | fleet10-orig-ransom-fanout-bury | original | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 11 | fleet11-art-scheduled-task | github_art | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 12 | fleet12-art-wmi-remote | github_art | **HELD** | 1.0 | - | - | host-c, host-e | - |
| 13 | fleet13-art-cloud-cred-egress | github_art | **HELD** | 1.0 | - | - | host-a, host-d, host-e | - |
| 14 | fleet14-art-rdp-hop | github_art | **HELD** | 1.0 | - | - | host-b, host-d | - |
| 15 | fleet15-art-mail-collect | github_art | **HELD** | 1.0 | - | - | host-c, host-d, host-e | - |
| 16 | fleet16-orig-dual-user-bridge | original | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 17 | fleet17-orig-dns-plus-lateral | original | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 18 | fleet18-orig-burst-retries | original | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 19 | fleet19-orig-helpdesk-vs-apt | original | **HELD** | 1.0 | - | - | host-d, host-e | - |
| 20 | fleet20-orig-cdn-plus-apt | original | **HELD** | 1.0 | - | - | host-d, host-e | - |

## Where it broke

No stable breaks — all attacks matched truth without over-merge.

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
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c, host-d
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
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=True
- Quarantine dry-run: host-a, host-b, host-c
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
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -

### fleet10-orig-ransom-fanout-bury

- Origin: `original` | Techniques: T1486, T1078, T1041
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -

### fleet11-art-scheduled-task

- Origin: `github_art` | Techniques: T1053.005, T1078, T1041
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -

### fleet12-art-wmi-remote

- Origin: `github_art` | Techniques: T1047, T1021, T1041
- Truth: host-a, host-b, host-d
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-d
- Saved: host-c, host-e | False Q: -

### fleet13-art-cloud-cred-egress

- Origin: `github_art` | Techniques: T1552.005, T1078, T1041
- Truth: host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-b, host-c
- Saved: host-a, host-d, host-e | False Q: -

### fleet14-art-rdp-hop

- Origin: `github_art` | Techniques: T1021.001, T1078, T1041
- Truth: host-a, host-c, host-e
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-c, host-e
- Saved: host-b, host-d | False Q: -

### fleet15-art-mail-collect

- Origin: `github_art` | Techniques: T1114, T1078, T1041
- Truth: host-a, host-b
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b
- Saved: host-c, host-d, host-e | False Q: -

### fleet16-orig-dual-user-bridge

- Origin: `original` | Techniques: T1078, T1041
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -

### fleet17-orig-dns-plus-lateral

- Origin: `original` | Techniques: T1071.004, T1078, T1041
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -

### fleet18-orig-burst-retries

- Origin: `original` | Techniques: T1110, T1078, T1041
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -

### fleet19-orig-helpdesk-vs-apt

- Origin: `original` | Techniques: T1078, T1041
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -

### fleet20-orig-cdn-plus-apt

- Origin: `original` | Techniques: T1105, T1078, T1041
- Truth: host-a, host-b, host-c
- Verdict: **HELD** | Jaccard=1.0 | fusion_lift=False
- Quarantine dry-run: host-a, host-b, host-c
- Saved: host-d, host-e | False Q: -

## Honesty

- Black-box narratives; scoring uses Corvex break-point machinery.
- DNS-only and window-gap packs are intentional stress cases.
- Live OS quarantine remains unimplemented.
