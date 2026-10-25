# Aggressive open-source attack eval (APT29 / APT3 / LSASS / Log4Shell / GoldenSAML)

Externally authored captures. **Not** Corvex-written fleet manifests.
**claim_allowed=False**. Lab purple-team only.

- Corpora scored: **14** | Wall: **62.9274s**
- Catalog: `labs/opensource/catalog.json`
- Attack inventory: [`opensource_aggressive_inventory.md`](opensource_aggressive_inventory.md)

## Verdict rollup (observational)

| Label | Count | Meaning |
|-------|-------|---------|
| **SINGLE_HOST** | 10 | Capture has <2 hosts — fusion not testable |
| **FUSION_HELD** | 4 | Multi-host campaign + correlator beat detector-only |

## Scoreboard

| Attack | Tool | Family | Verdict | Hosts | Events | Lift | Q all? | Breaks |
|--------|------|--------|---------|-------|--------|------|--------|--------|
| ATT&CK Evals Round 2 APT29 day1 (full multi-host | MITRE ATT&CK Evals R2 (manual) | compound_apt29 | **FUSION_HELD** | 4 | 10980 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.944 (adapted=10980, skipp… |
| ↳ techniques `G0016,APT29,CozyBear` | | | | | | | | |
| ATT&CK Evals Round 2 APT29 day2 (full multi-host | MITRE ATT&CK Evals R2 (manual) | compound_apt29 | **FUSION_HELD** | 4 | 67693 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.8847 (adapted=67693, skip… |
| ↳ techniques `G0016,APT29,CozyBear` | | | | | | | | |
| ATT&CK Evals Round 1 APT3 day1 (full scenario) | Caldera (MITRE ATT&CK Evals R1) | compound_apt3 | **FUSION_HELD** | 5 | 14423 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.8585 (adapted=14423, skip… |
| ↳ techniques `G0022,APT3` | | | | | | | | |
| Empire APT3 multi-day compound | Empire (OTRF APT3 compound) | compound_apt3 | **SINGLE_HOST** | 1 | 7571 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| ↳ techniques `G0022,APT3` | | | | | | | | |
| Golden SAML ADFS mail-access — Windows host even | Golden SAML / ADFS | identity_federation | **FUSION_HELD** | 2 | 29 | 0 | no | — |
| ↳ techniques `T1606.002,T1552` | | | | | | | | |
| Log4Shell JNDI exploit — Security auditing host | Log4Shell CVE-2021-44228 | exploit_cve | **SINGLE_HOST** | 1 | 5 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| ↳ techniques `T1190,T1059.007` | | | | | | | | |
| Log4Shell JNDI exploit — Sysmon host telemetry | Log4Shell CVE-2021-44228 | exploit_cve | **SINGLE_HOST** | 1 | 9 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| ↳ techniques `T1190,T1059.007` | | | | | | | | |
| LSASS campaign: comsvcs MiniDump | Metasploit/comsvcs | credential_dump_campaign | **SINGLE_HOST** | 1 | 1158 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| ↳ techniques `T1003.001` | | | | | | | | |
| LSASS campaign: Outflank Dumpert (syscalls) | Metasploit/Outflank Dumpert | credential_dump_campaign | **SINGLE_HOST** | 1 | 1379 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| ↳ techniques `T1003.001` | | | | | | | | |
| LSASS campaign: Mimikatz logonpasswords memory d | Metasploit | credential_dump_campaign | **SINGLE_HOST** | 1 | 1238 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| ↳ techniques `T1003.001` | | | | | | | | |
| LSASS campaign: NanoDump (evasive) | Metasploit/NanoDump | credential_dump_campaign | **SINGLE_HOST** | 1 | 1112 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| ↳ techniques `T1003.001` | | | | | | | | |
| LSASS campaign: Out-Minidump PowerShell | Metasploit/Out-Minidump | credential_dump_campaign | **SINGLE_HOST** | 1 | 1209 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| ↳ techniques `T1003.001` | | | | | | | | |
| LSASS campaign: ProcDump LSASS memory dump | Metasploit/ProcDump | credential_dump_campaign | **SINGLE_HOST** | 1 | 1076 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| ↳ techniques `T1003.001` | | | | | | | | |
| LSASS campaign: SharpDump | Metasploit/SharpDump | credential_dump_campaign | **SINGLE_HOST** | 1 | 1573 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| ↳ techniques `T1003.001` | | | | | | | | |

## Where it breaks (every flagged corpus)

### `otrf-apt29-day1` — ATT&CK Evals Round 2 APT29 day1 (full multi-host) (MITRE ATT&CK Evals R2 (manual))

- **Verdict:** `FUSION_HELD`
- **Techniques:** G0016, APT29, CozyBear
- **Hosts/events:** 4 / 10980
- **Skip rate:** 0.944
- **Corr bridge hosts:** nashua, newyork, scranton, utica
- **Q dry-run:** newyork, scranton, utica
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.944 (adapted=10980, skipped=185101) — channel allowlist blind spot

### `otrf-apt29-day2` — ATT&CK Evals Round 2 APT29 day2 (full multi-host) (MITRE ATT&CK Evals R2 (manual))

- **Verdict:** `FUSION_HELD`
- **Techniques:** G0016, APT29, CozyBear
- **Hosts/events:** 4 / 67693
- **Skip rate:** 0.8847
- **Corr bridge hosts:** nashua, newyork, scranton, utica
- **Q dry-run:** newyork, scranton, utica
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8847 (adapted=67693, skipped=519593) — channel allowlist blind spot

### `otrf-caldera-apt3-day1` — ATT&CK Evals Round 1 APT3 day1 (full scenario) (Caldera (MITRE ATT&CK Evals R1))

- **Verdict:** `FUSION_HELD`
- **Techniques:** G0022, APT3
- **Hosts/events:** 5 / 14423
- **Skip rate:** 0.8585
- **Corr bridge hosts:** acct001, file001, hfdc01, hr001, it001
- **Q dry-run:** hfdc01, hr001, it001
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8585 (adapted=14423, skipped=87481) — channel allowlist blind spot

### `otrf-empire-apt3` — Empire APT3 multi-day compound (Empire (OTRF APT3 compound))

- **Verdict:** `SINGLE_HOST`
- **Techniques:** G0022, APT3
- **Hosts/events:** 1 / 7571
- **Skip rate:** 0.9378
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9378 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9378 (adapted=7571, skipped=114088) — channel allowlist blind spot

### `otrf-log4shell-security` — Log4Shell JNDI exploit — Security auditing host (Log4Shell CVE-2021-44228)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** T1190, T1059.007
- **Hosts/events:** 1 / 5
- **Skip rate:** 0.8718
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.8718 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8718 (adapted=5, skipped=34) — channel allowlist blind spot

### `otrf-log4shell-sysmon` — Log4Shell JNDI exploit — Sysmon host telemetry (Log4Shell CVE-2021-44228)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** T1190, T1059.007
- **Hosts/events:** 1 / 9
- **Skip rate:** 0.9815
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9815 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9815 (adapted=9, skipped=478) — channel allowlist blind spot

### `otrf-lsass-metasploit-comsvcs` — LSASS campaign: comsvcs MiniDump (Metasploit/comsvcs)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** T1003.001
- **Hosts/events:** 1 / 1158
- **Skip rate:** 0.9724
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9724 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9724 (adapted=1158, skipped=40796) — channel allowlist blind spot

### `otrf-lsass-metasploit-dumpert` — LSASS campaign: Outflank Dumpert (syscalls) (Metasploit/Outflank Dumpert)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** T1003.001
- **Hosts/events:** 1 / 1379
- **Skip rate:** 0.9763
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9763 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9763 (adapted=1379, skipped=56717) — channel allowlist blind spot

### `otrf-lsass-metasploit-logonpasswords` — LSASS campaign: Mimikatz logonpasswords memory dump (Metasploit)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** T1003.001
- **Hosts/events:** 1 / 1238
- **Skip rate:** 0.9769
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9769 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9769 (adapted=1238, skipped=52460) — channel allowlist blind spot

### `otrf-lsass-metasploit-nanodump` — LSASS campaign: NanoDump (evasive) (Metasploit/NanoDump)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** T1003.001
- **Hosts/events:** 1 / 1112
- **Skip rate:** 0.9807
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9807 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9807 (adapted=1112, skipped=56612) — channel allowlist blind spot

### `otrf-lsass-metasploit-out-minidump` — LSASS campaign: Out-Minidump PowerShell (Metasploit/Out-Minidump)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** T1003.001
- **Hosts/events:** 1 / 1209
- **Skip rate:** 0.9702
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9702 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9702 (adapted=1209, skipped=39359) — channel allowlist blind spot

### `otrf-lsass-metasploit-procdump` — LSASS campaign: ProcDump LSASS memory dump (Metasploit/ProcDump)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** T1003.001
- **Hosts/events:** 1 / 1076
- **Skip rate:** 0.9747
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9747 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9747 (adapted=1076, skipped=41406) — channel allowlist blind spot

### `otrf-lsass-metasploit-sharpdump` — LSASS campaign: SharpDump (Metasploit/SharpDump)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** T1003.001
- **Hosts/events:** 1 / 1573
- **Skip rate:** 0.9737
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9737 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9737 (adapted=1573, skipped=58134) — channel allowlist blind spot


## Honesty

- Authorship: OTRF / MITRE ATT&CK Evals Caldera — **external**.
- Observational metrics (no Corvex-authored ground-truth F1).
- Sanitized JSONL drops CommandLine/ScriptBlockText (Defender PUA).
- `claim_allowed` stays false.

## Reproduce

```bash
python scripts/fetch_opensource_corpora.py --aggressive
python scripts/run_opensource_attack_eval.py --aggressive
```

