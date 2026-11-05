# Aggressive attacks used (inventory)

Every corpus scored in this eval. Authorship = OTRF / MITRE.

Generated: **2026-10-23T17:55:29Z** | N=**14**

| # | ID | Attack | Tool | ATT&CK / techniques | Family | Verdict | Breaks? |
|---|----|--------|------|---------------------|--------|---------|---------|
| 1 | `otrf-apt29-day1` | ATT&CK Evals Round 2 APT29 day1 (full multi-host) | MITRE ATT&CK Evals R2 (manual) | G0016, APT29, CozyBear | compound_apt29 | **FUSION_HELD** | yes |
| 2 | `otrf-apt29-day2` | ATT&CK Evals Round 2 APT29 day2 (full multi-host) | MITRE ATT&CK Evals R2 (manual) | G0016, APT29, CozyBear | compound_apt29 | **FUSION_HELD** | yes |
| 3 | `otrf-caldera-apt3-day1` | ATT&CK Evals Round 1 APT3 day1 (full scenario) | Caldera (MITRE ATT&CK Evals R1) | G0022, APT3 | compound_apt3 | **FUSION_HELD** | yes |
| 4 | `otrf-empire-apt3` | Empire APT3 multi-day compound | Empire (OTRF APT3 compound) | G0022, APT3 | compound_apt3 | **SINGLE_HOST** | yes |
| 5 | `otrf-goldensaml-windows` | Golden SAML ADFS mail-access — Windows host events | Golden SAML / ADFS | T1606.002, T1552 | identity_federation | **FUSION_HELD** | no |
| 6 | `otrf-log4shell-security` | Log4Shell JNDI exploit — Security auditing host | Log4Shell CVE-2021-44228 | T1190, T1059.007 | exploit_cve | **SINGLE_HOST** | yes |
| 7 | `otrf-log4shell-sysmon` | Log4Shell JNDI exploit — Sysmon host telemetry | Log4Shell CVE-2021-44228 | T1190, T1059.007 | exploit_cve | **SINGLE_HOST** | yes |
| 8 | `otrf-lsass-metasploit-comsvcs` | LSASS campaign: comsvcs MiniDump | Metasploit/comsvcs | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |
| 9 | `otrf-lsass-metasploit-dumpert` | LSASS campaign: Outflank Dumpert (syscalls) | Metasploit/Outflank Dumpert | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |
| 10 | `otrf-lsass-metasploit-logonpasswords` | LSASS campaign: Mimikatz logonpasswords memory dump | Metasploit | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |
| 11 | `otrf-lsass-metasploit-nanodump` | LSASS campaign: NanoDump (evasive) | Metasploit/NanoDump | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |
| 12 | `otrf-lsass-metasploit-out-minidump` | LSASS campaign: Out-Minidump PowerShell | Metasploit/Out-Minidump | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |
| 13 | `otrf-lsass-metasploit-procdump` | LSASS campaign: ProcDump LSASS memory dump | Metasploit/ProcDump | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |
| 14 | `otrf-lsass-metasploit-sharpdump` | LSASS campaign: SharpDump | Metasploit/SharpDump | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |

## By tool

| Tool | Verdicts |
|------|----------|
| Caldera (MITRE ATT&CK Evals R1) | FUSION_HELD=1 |
| Empire (OTRF APT3 compound) | SINGLE_HOST=1 |
| Golden SAML / ADFS | FUSION_HELD=1 |
| Log4Shell CVE-2021-44228 | SINGLE_HOST=2 |
| MITRE ATT&CK Evals R2 (manual) | FUSION_HELD=2 |
| Metasploit | SINGLE_HOST=1 |
| Metasploit/NanoDump | SINGLE_HOST=1 |
| Metasploit/Out-Minidump | SINGLE_HOST=1 |
| Metasploit/Outflank Dumpert | SINGLE_HOST=1 |
| Metasploit/ProcDump | SINGLE_HOST=1 |
| Metasploit/SharpDump | SINGLE_HOST=1 |
| Metasploit/comsvcs | SINGLE_HOST=1 |

## By ATT&CK family

| Family | Verdicts |
|--------|----------|
| compound_apt29 | FUSION_HELD=2 |
| compound_apt3 | FUSION_HELD=1, SINGLE_HOST=1 |
| credential_dump_campaign | SINGLE_HOST=7 |
| exploit_cve | SINGLE_HOST=2 |
| identity_federation | FUSION_HELD=1 |

## Upstream

- https://github.com/OTRF/Security-Datasets
- APT3 / APT29: MITRE ATT&CK Evals via Caldera / Empire / manual compounds
- LSASS: Metasploit dump technique variants (OTRF compound campaigns)

