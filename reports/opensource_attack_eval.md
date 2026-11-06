# Open-source attack eval (OTRF / Security-Datasets)

Externally authored captures. **Not** Corvex-written fleet manifests.
**claim_allowed=False**. Lab purple-team only.

- Corpora scored: **76** | Wall: **26.4557s**
- Catalog: `labs/opensource/catalog.json`
- Attack inventory: [`opensource_attack_inventory.md`](opensource_attack_inventory.md)

## Verdict rollup (observational)

| Label | Count | Meaning |
|-------|-------|---------|
| **FUSION_HELD** | 35 | Multi-host campaign + correlator beat detector-only |
| **MULTI_HOST_NO_LIFT** | 18 | Multi-host present; fusion adds no host-coverage lift |
| **SINGLE_HOST** | 17 | Capture has <2 hosts — fusion not testable |
| **ERROR** | 5 | Fetch/adapt/score failed |
| **BLIND** | 1 | No campaigns from adapted events |

## Scoreboard

| Attack | Tool | Family | Verdict | Hosts | Events | Lift | Q all? | Breaks |
|--------|------|--------|---------|-------|--------|------|--------|--------|
| ATT&CK Evals Round 2 APT29 day1 (full multi-host | MITRE ATT&CK Evals R2 (manual) | compound_apt29 | **ERROR** | — | — | — | no | ERROR: no raw JSON under C:\Users\siddu\projects\corvex\l… |
| ↳ techniques `G0016,APT29,CozyBear` | | | | | | | | |
| ATT&CK Evals Round 2 APT29 day2 (full multi-host | MITRE ATT&CK Evals R2 (manual) | compound_apt29 | **ERROR** | — | — | — | no | ERROR: no raw JSON under C:\Users\siddu\projects\corvex\l… |
| ↳ techniques `G0016,APT29,CozyBear` | | | | | | | | |
| ATT&CK Evals Round 1 APT3 day1 (full scenario) | Caldera (MITRE ATT&CK Evals R1) | compound_apt3 | **FUSION_HELD** | 5 | 14423 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.8585 (adapted=14423, skip… |
| ↳ techniques `G0022,APT3` | | | | | | | | |
| cmd dumping ntds dit file volume shadow copy | native | credential_access | **SINGLE_HOST** | 1 | 612 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| cmd seatbelt group user | native | discovery | **SINGLE_HOST** | 1 | 3 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| cmd service mod fax | native | privilege_escalation | **SINGLE_HOST** | 1 | 6 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| cmd sharpview pcre net | native | execution | **SINGLE_HOST** | 1 | 8 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| DCOM Excel4Macro (allowed) | Covenant | lateral_movement | **FUSION_HELD** | 3 | 290 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9643 (adapted=290, skippe… |
| ↳ techniques `T1021.003,T1137.001` | | | | | | | | |
| covenant dcom iertutil dll hijack | Covenant | lateral_movement | **FUSION_HELD** | 3 | 548 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9855 (adapted=548, skippe… |
| covenant dcom registerxll | Covenant | lateral_movement | **FUSION_HELD** | 3 | 362 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9342 (adapted=362, skippe… |
| COM/WSMAN automation | Covenant | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 87 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1021.003,T1021.006` | | | | | | | | |
| DCSync DsGetNCChanges | Covenant | credential_access | **FUSION_HELD** | 3 | 113 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.87 (adapted=113, skipped=… |
| ↳ techniques `T1003.006` | | | | | | | | |
| InstallUtil LOLBAS | Covenant | defense_evasion | **FUSION_HELD** | 3 | 93 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9462 (adapted=93, skipped… |
| ↳ techniques `T1218.004` | | | | | | | | |
| LDAP search Domain Admins | Covenant | discovery | **MULTI_HOST_NO_LIFT** | 3 | 51 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1069.002,T1087.002` | | | | | | | | |
| PS remoting command | Covenant | lateral_movement | **FUSION_HELD** | 3 | 209 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9512 (adapted=209, skippe… |
| ↳ techniques `T1021.006` | | | | | | | | |
| PS remoting Grunt implant | Covenant | lateral_movement | **FUSION_HELD** | 5 | 1069 | 0 | no | — |
| ↳ techniques `T1021.006` | | | | | | | | |
| covenant sharpsc create dcerpc smb svcctl | Covenant | lateral_movement | **FUSION_HELD** | 3 | 260 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9233 (adapted=260, skippe… |
| covenant sharpsc start dcerpc smb svcctl | Covenant | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 336 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| SharpWMI create via DCERPC | Covenant | lateral_movement | **FUSION_HELD** | 3 | 184 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9215 (adapted=184, skippe… |
| ↳ techniques `T1047` | | | | | | | | |
| SMB copy CreateRequest | Covenant | lateral_movement | **FUSION_HELD** | 3 | 39 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9229 (adapted=39, skipped… |
| ↳ techniques `T1021.002,T1570` | | | | | | | | |
| WMI remote event subscription (ActiveScript) | Covenant | lateral_movement | **FUSION_HELD** | 3 | 300 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9193 (adapted=300, skippe… |
| ↳ techniques `T1047,T1546.003` | | | | | | | | |
| WMI wbemcomn.dll hijack | Covenant | lateral_movement | **FUSION_HELD** | 3 | 418 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9533 (adapted=418, skippe… |
| ↳ techniques `T1047,T1574.001` | | | | | | | | |
| Empire APT3 multi-day compound | Empire (OTRF APT3 compound) | compound_apt3 | **ERROR** | — | — | — | no | ERROR: no raw JSON under C:\Users\siddu\projects\corvex\l… |
| ↳ techniques `G0022,APT3` | | | | | | | | |
| DCOM ShellWindows stager | Empire | lateral_movement | **FUSION_HELD** | 3 | 521 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9841 (adapted=521, skippe… |
| ↳ techniques `T1021.003` | | | | | | | | |
| DCSync DsGetNCChanges | Empire | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 3674 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1003.006` | | | | | | | | |
| LoadLibrary CreateRemoteThread inject | Empire | defense_evasion | **BLIND** | 3 | 2282 | -3 | no | BLIND: no campaigns — detectors/channels may not map this… |
| ↳ techniques `T1055.001` | | | | | | | | |
| Find local admin via OpenSCManager | Empire | discovery | **FUSION_HELD** | 3 | 880 | 0 | no | — |
| ↳ techniques `T1069.001,T1018` | | | | | | | | |
| empire launcher vbs | Empire | execution | **FUSION_HELD** | 3 | 147 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9289 (adapted=147, skippe… |
| empire mimikatz backupkeys dcerpc smb lsarpc | Empire | credential_access | **MULTI_HOST_NO_LIFT** | 4 | 3544 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| empire mimikatz extract keys | Empire | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 3586 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| Mimikatz sekurlsa::logonpasswords | Empire/Mimikatz | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 2011 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1003.001` | | | | | | | | |
| empire mimikatz lsadump patch | Empire | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 2774 | -1 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| Mimikatz SAM access | Empire/Mimikatz | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 3376 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1003.002` | | | | | | | | |
| MSBuild via WMI/SMB | Empire | lateral_movement | **FUSION_HELD** | 3 | 437 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9041 (adapted=437, skippe… |
| ↳ techniques `T1047,T1127.001` | | | | | | | | |
| NetSessEnum session enum | Empire | discovery | **MULTI_HOST_NO_LIFT** | 3 | 724 | -1 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1049` | | | | | | | | |
| empire ninjacopy dumping ntds dit file | Empire | credential_access | **SINGLE_HOST** | 1 | 1221 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| Over-PTH / LSASS patch | Empire | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 4082 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1550.002,T1003.001` | | | | | | | | |
| empire persistence registry modification run key | Empire | persistence | **FUSION_HELD** | 3 | 1825 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.955 (adapted=1825, skippe… |
| empire powerview ldap ntsecuritydescriptor | Empire | defense_evasion | **FUSION_HELD** | 3 | 3052 | 0 | no | — |
| PsExec / svcctl remote service | Empire | lateral_movement | **FUSION_HELD** | 3 | 462 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.8937 (adapted=462, skippe… |
| ↳ techniques `T1021.002,T1570` | | | | | | | | |
| empire psinject PEinjection | Empire | defense_evasion | **MULTI_HOST_NO_LIFT** | 3 | 2302 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| PowerShell remoting stager | Empire | lateral_movement | **FUSION_HELD** | 3 | 245 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9107 (adapted=245, skippe… |
| ↳ techniques `T1021.006` | | | | | | | | |
| regsvr32 SCT launcher | Empire | defense_evasion | **FUSION_HELD** | 2 | 309 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.8707 (adapted=309, skippe… |
| ↳ techniques `T1218.010` | | | | | | | | |
| Rubeus asktgt + PTT | Empire/Rubeus | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 217 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1558.001,T1550.003` | | | | | | | | |
| Registry Run keys (elevated) | Empire | persistence | **FUSION_HELD** | 3 | 314 | 0 | no | — |
| ↳ techniques `T1547.001` | | | | | | | | |
| SAMR EnumDomainUsers | Empire | discovery | **MULTI_HOST_NO_LIFT** | 3 | 110 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1087.002` | | | | | | | | |
| empire schtasks creation standard user | Empire | persistence | **FUSION_HELD** | 3 | 246 | 0 | no | — |
| Schtasks create (elevated) | Empire | persistence | **FUSION_HELD** | 3 | 1710 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9712 (adapted=1710, skipp… |
| ↳ techniques `T1053.005` | | | | | | | | |
| Remote service DLL hijack | Empire | lateral_movement | **FUSION_HELD** | 3 | 920 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.8551 (adapted=920, skippe… |
| ↳ techniques `T1574.001,T1543.003` | | | | | | | | |
| empire shell net local users | Empire | discovery | **ERROR** | — | — | — | no | ERROR: no raw JSON under C:\Users\siddu\projects\corvex\l… |
| empire shell net localgroup administrators | Empire | discovery | **ERROR** | — | — | — | no | ERROR: no raw JSON under C:\Users\siddu\projects\corvex\l… |
| empire shell rpc samr smb group domain admins st | Empire | discovery | **FUSION_HELD** | 3 | 198 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.8868 (adapted=198, skippe… |
| empire shell rubeus asktgt createnetonly | Empire | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 263 | -1 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| smbexec via svcctl | Empire | lateral_movement | **FUSION_HELD** | 3 | 516 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9312 (adapted=516, skippe… |
| ↳ techniques `T1021.002` | | | | | | | | |
| empire uac shellapi fodhelper | Empire | privilege_escalation | **MULTI_HOST_NO_LIFT** | 3 | 324 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| WMI local event subscription | Empire | persistence | **FUSION_HELD** | 3 | 1897 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9763 (adapted=1897, skipp… |
| ↳ techniques `T1546.003` | | | | | | | | |
| WMI IWbemServices ExecMethod | Empire | lateral_movement | **FUSION_HELD** | 3 | 641 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.8996 (adapted=641, skippe… |
| ↳ techniques `T1047` | | | | | | | | |
| empire wmic add user backdoor | Empire | lateral_movement | **FUSION_HELD** | 3 | 411 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9665 (adapted=411, skippe… |
| empire wmic add user backdoor | Empire | defense_evasion | **FUSION_HELD** | 3 | 411 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9665 (adapted=411, skippe… |
| Golden SAML ADFS mail-access — Windows host even | Golden SAML / ADFS | identity_federation | **MULTI_HOST_NO_LIFT** | 2 | 29 | 0 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
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
| msf record mic | Metasploit | collection | **MULTI_HOST_NO_LIFT** | 3 | 232 | -1 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ntdsutil NTDS.dit dump | native | credential_access | **SINGLE_HOST** | 1 | 285 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| ↳ techniques `T1003.003` | | | | | | | | |
| proxylogon ssrf rce poc | native | persistence | **SINGLE_HOST** | 1 | 296 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| psh python webserver | native | execution | **SINGLE_HOST** | 1 | 8 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| PurpleSharp AD playbook I (multi-step) | PurpleSharp | playbook | **FUSION_HELD** | 4 | 780 | 1 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.97 (adapted=780, skipped=… |
| ↳ techniques `T1021,T1078,T1087` | | | | | | | | |
| Remote scheduled task create | native | persistence_lateral | **FUSION_HELD** | 2 | 35 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9664 (adapted=35, skipped… |
| ↳ techniques `T1053.005,T1021` | | | | | | | | |
| schtask modification | native | lateral_movement | **FUSION_HELD** | 2 | 46 | 0 | no | ADAPTER_HEAVY_SKIP: skip_rate=0.9827 (adapted=46, skipped… |

## Where it breaks (every flagged corpus)

### `otrf-apt29-day1` — ATT&CK Evals Round 2 APT29 day1 (full multi-host) (MITRE ATT&CK Evals R2 (manual))

- **Verdict:** `ERROR`
- **Techniques:** G0016, APT29, CozyBear
- **Hosts/events:** None / None
- **Skip rate:** None
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** ERROR: no raw JSON under C:\Users\siddu\projects\corvex\labs\opensource\otrf-apt29-day1\raw

### `otrf-apt29-day2` — ATT&CK Evals Round 2 APT29 day2 (full multi-host) (MITRE ATT&CK Evals R2 (manual))

- **Verdict:** `ERROR`
- **Techniques:** G0016, APT29, CozyBear
- **Hosts/events:** None / None
- **Skip rate:** None
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** ERROR: no raw JSON under C:\Users\siddu\projects\corvex\labs\opensource\otrf-apt29-day2\raw

### `otrf-empire-apt3` — Empire APT3 multi-day compound (Empire (OTRF APT3 compound))

- **Verdict:** `ERROR`
- **Techniques:** G0022, APT3
- **Hosts/events:** None / None
- **Skip rate:** None
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** ERROR: no raw JSON under C:\Users\siddu\projects\corvex\labs\opensource\otrf-empire-apt3\raw

### `otrf-empire-dll-inject` — LoadLibrary CreateRemoteThread inject (Empire)

- **Verdict:** `BLIND`
- **Techniques:** T1055.001
- **Hosts/events:** 3 / 2282
- **Skip rate:** 0.813
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** BLIND: no campaigns — detectors/channels may not map this capture

### `otrf-empire-shell-net-local-users` — empire shell net local users (Empire)

- **Verdict:** `ERROR`
- **Techniques:** —
- **Hosts/events:** None / None
- **Skip rate:** None
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** ERROR: no raw JSON under C:\Users\siddu\projects\corvex\labs\opensource\otrf-empire-shell-net-local-users\raw

### `otrf-empire-shell-net-localgroup-administrators` — empire shell net localgroup administrators (Empire)

- **Verdict:** `ERROR`
- **Techniques:** —
- **Hosts/events:** None / None
- **Skip rate:** None
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** ERROR: no raw JSON under C:\Users\siddu\projects\corvex\labs\opensource\otrf-empire-shell-net-localgroup-administrators\raw

### `otrf-caldera-apt3-day1` — ATT&CK Evals Round 1 APT3 day1 (full scenario) (Caldera (MITRE ATT&CK Evals R1))

- **Verdict:** `FUSION_HELD`
- **Techniques:** G0022, APT3
- **Hosts/events:** 5 / 14423
- **Skip rate:** 0.8585
- **Corr bridge hosts:** acct001, file001, hfdc01, hr001, it001
- **Q dry-run:** hfdc01
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8585 (adapted=14423, skipped=87481) — channel allowlist blind spot

### `otrf-cmd-dumping-ntds-dit-file-volume-shadow-copy` — cmd dumping ntds dit file volume shadow copy (native)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** —
- **Hosts/events:** 1 / 612
- **Skip rate:** 0.9637
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9637 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9637 (adapted=612, skipped=16231) — channel allowlist blind spot

### `otrf-cmd-seatbelt-group-user` — cmd seatbelt group user (native)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** —
- **Hosts/events:** 1 / 3
- **Skip rate:** 0.9933
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9933 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9933 (adapted=3, skipped=448) — channel allowlist blind spot

### `otrf-cmd-service-mod-fax` — cmd service mod fax (native)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** —
- **Hosts/events:** 1 / 6
- **Skip rate:** 0.9863
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9863 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9863 (adapted=6, skipped=431) — channel allowlist blind spot

### `otrf-cmd-sharpview-pcre-net` — cmd sharpview pcre net (native)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** —
- **Hosts/events:** 1 / 8
- **Skip rate:** 0.97
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.97 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.97 (adapted=8, skipped=259) — channel allowlist blind spot

### `otrf-covenant-dcom-excel4` — DCOM Excel4Macro (allowed) (Covenant)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1021.003, T1137.001
- **Hosts/events:** 3 / 290
- **Skip rate:** 0.9643
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9643 (adapted=290, skipped=7831) — channel allowlist blind spot

### `otrf-covenant-dcom-iertutil-dll-hijack` — covenant dcom iertutil dll hijack (Covenant)

- **Verdict:** `FUSION_HELD`
- **Techniques:** —
- **Hosts/events:** 3 / 548
- **Skip rate:** 0.9855
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation5
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9855 (adapted=548, skipped=37266) — channel allowlist blind spot

### `otrf-covenant-dcom-registerxll` — covenant dcom registerxll (Covenant)

- **Verdict:** `FUSION_HELD`
- **Techniques:** —
- **Hosts/events:** 3 / 362
- **Skip rate:** 0.9342
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9342 (adapted=362, skipped=5142) — channel allowlist blind spot

### `otrf-covenant-dcom-wsman` — COM/WSMAN automation (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1021.003, T1021.006
- **Hosts/events:** 3 / 87
- **Skip rate:** 0.8927
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8927 (adapted=87, skipped=724) — channel allowlist blind spot

### `otrf-covenant-dcsync` — DCSync DsGetNCChanges (Covenant)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1003.006
- **Hosts/events:** 3 / 113
- **Skip rate:** 0.87
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation5
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.87 (adapted=113, skipped=756) — channel allowlist blind spot

### `otrf-covenant-installutil` — InstallUtil LOLBAS (Covenant)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1218.004
- **Hosts/events:** 3 / 93
- **Skip rate:** 0.9462
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9462 (adapted=93, skipped=1637) — channel allowlist blind spot

### `otrf-covenant-ldap-domain-admins` — LDAP search Domain Admins (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1069.002, T1087.002
- **Hosts/events:** 3 / 51
- **Skip rate:** 0.9176
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** workstation5
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9176 (adapted=51, skipped=568) — channel allowlist blind spot

### `otrf-covenant-psremoting` — PS remoting command (Covenant)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1021.006
- **Hosts/events:** 3 / 209
- **Skip rate:** 0.9512
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9512 (adapted=209, skipped=4075) — channel allowlist blind spot

### `otrf-covenant-sharpsc-create-dcerpc-smb-svcctl` — covenant sharpsc create dcerpc smb svcctl (Covenant)

- **Verdict:** `FUSION_HELD`
- **Techniques:** —
- **Hosts/events:** 3 / 260
- **Skip rate:** 0.9233
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9233 (adapted=260, skipped=3130) — channel allowlist blind spot

### `otrf-covenant-sharpsc-start-dcerpc-smb-svcctl` — covenant sharpsc start dcerpc smb svcctl (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** —
- **Hosts/events:** 3 / 336
- **Skip rate:** 0.9444
- **Corr bridge hosts:** workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9444 (adapted=336, skipped=5710) — channel allowlist blind spot

### `otrf-covenant-sharpwmi` — SharpWMI create via DCERPC (Covenant)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1047
- **Hosts/events:** 3 / 184
- **Skip rate:** 0.9215
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9215 (adapted=184, skipped=2159) — channel allowlist blind spot

### `otrf-covenant-smb-copy` — SMB copy CreateRequest (Covenant)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1021.002, T1570
- **Hosts/events:** 3 / 39
- **Skip rate:** 0.9229
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9229 (adapted=39, skipped=467) — channel allowlist blind spot

### `otrf-covenant-wmi-event-sub` — WMI remote event subscription (ActiveScript) (Covenant)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1047, T1546.003
- **Hosts/events:** 3 / 300
- **Skip rate:** 0.9193
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9193 (adapted=300, skipped=3419) — channel allowlist blind spot

### `otrf-covenant-wmi-hijack` — WMI wbemcomn.dll hijack (Covenant)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1047, T1574.001
- **Hosts/events:** 3 / 418
- **Skip rate:** 0.9533
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9533 (adapted=418, skipped=8529) — channel allowlist blind spot

### `otrf-empire-dcom-shellwindows` — DCOM ShellWindows stager (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1021.003
- **Hosts/events:** 3 / 521
- **Skip rate:** 0.9841
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9841 (adapted=521, skipped=32185) — channel allowlist blind spot

### `otrf-empire-dcsync` — DCSync DsGetNCChanges (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1003.006
- **Hosts/events:** 3 / 3674
- **Skip rate:** 0.566
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** workstation5
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

### `otrf-empire-launcher-vbs` — empire launcher vbs (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** —
- **Hosts/events:** 3 / 147
- **Skip rate:** 0.9289
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation5, workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9289 (adapted=147, skipped=1920) — channel allowlist blind spot

### `otrf-empire-mimikatz-backupkeys-dcerpc-smb-lsarpc` — empire mimikatz backupkeys dcerpc smb lsarpc (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** —
- **Hosts/events:** 4 / 3544
- **Skip rate:** 0.5507
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** workstation5
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

### `otrf-empire-mimikatz-extract-keys` — empire mimikatz extract keys (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** —
- **Hosts/events:** 3 / 3586
- **Skip rate:** 0.7283
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

### `otrf-empire-mimikatz-logonpasswords` — Mimikatz sekurlsa::logonpasswords (Empire/Mimikatz)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1003.001
- **Hosts/events:** 3 / 2011
- **Skip rate:** 0.6663
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** workstation5
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

### `otrf-empire-mimikatz-lsadump-patch` — empire mimikatz lsadump patch (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** —
- **Hosts/events:** 3 / 2774
- **Skip rate:** 0.6027
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** workstation5
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

### `otrf-empire-mimikatz-sam` — Mimikatz SAM access (Empire/Mimikatz)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1003.002
- **Hosts/events:** 3 / 3376
- **Skip rate:** 0.7266
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** workstation5
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

### `otrf-empire-msbuild-wmi-smb` — MSBuild via WMI/SMB (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1047, T1127.001
- **Hosts/events:** 3 / 437
- **Skip rate:** 0.9041
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9041 (adapted=437, skipped=4122) — channel allowlist blind spot

### `otrf-empire-netsession` — NetSessEnum session enum (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1049
- **Hosts/events:** 3 / 724
- **Skip rate:** 0.8565
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** workstation5
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8565 (adapted=724, skipped=4323) — channel allowlist blind spot

### `otrf-empire-ninjacopy-dumping-ntds-dit-file` — empire ninjacopy dumping ntds dit file (Empire)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** —
- **Hosts/events:** 1 / 1221
- **Skip rate:** 0.9126
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9126 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9126 (adapted=1221, skipped=12748) — channel allowlist blind spot

### `otrf-empire-over-pth` — Over-PTH / LSASS patch (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1550.002, T1003.001
- **Hosts/events:** 3 / 4082
- **Skip rate:** 0.6026
- **Corr bridge hosts:** mordordc, workstation6
- **Q dry-run:** workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

### `otrf-empire-persistence-registry-modification-run-keys-` — empire persistence registry modification run keys standard user (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** —
- **Hosts/events:** 3 / 1825
- **Skip rate:** 0.955
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation5
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.955 (adapted=1825, skipped=38744) — channel allowlist blind spot

### `otrf-empire-psexec` — PsExec / svcctl remote service (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1021.002, T1570
- **Hosts/events:** 3 / 462
- **Skip rate:** 0.8937
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation5, workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8937 (adapted=462, skipped=3886) — channel allowlist blind spot

### `otrf-empire-psinject-injection` — empire psinject PEinjection (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** —
- **Hosts/events:** 3 / 2302
- **Skip rate:** 0.6097
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** workstation5
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

### `otrf-empire-psremoting` — PowerShell remoting stager (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1021.006
- **Hosts/events:** 3 / 245
- **Skip rate:** 0.9107
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation5, workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9107 (adapted=245, skipped=2499) — channel allowlist blind spot

### `otrf-empire-regsvr32-sct` — regsvr32 SCT launcher (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1218.010
- **Hosts/events:** 2 / 309
- **Skip rate:** 0.8707
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** workstation5
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8707 (adapted=309, skipped=2081) — channel allowlist blind spot

### `otrf-empire-rubeus-asktgt` — Rubeus asktgt + PTT (Empire/Rubeus)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1558.001, T1550.003
- **Hosts/events:** 3 / 217
- **Skip rate:** 0.8159
- **Corr bridge hosts:** mordordc, workstation6
- **Q dry-run:** workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

### `otrf-empire-samr-enum-users` — SAMR EnumDomainUsers (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1087.002
- **Hosts/events:** 3 / 110
- **Skip rate:** 0.8262
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** workstation5
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

### `otrf-empire-schtasks-elevated` — Schtasks create (elevated) (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1053.005
- **Hosts/events:** 3 / 1710
- **Skip rate:** 0.9712
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation5
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9712 (adapted=1710, skipped=57689) — channel allowlist blind spot

### `otrf-empire-service-dll-hijack` — Remote service DLL hijack (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1574.001, T1543.003
- **Hosts/events:** 3 / 920
- **Skip rate:** 0.8551
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8551 (adapted=920, skipped=5429) — channel allowlist blind spot

### `otrf-empire-shell-rpc-samr-smb-group-domain-admins-stan` — empire shell rpc samr smb group domain admins standard user (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** —
- **Hosts/events:** 3 / 198
- **Skip rate:** 0.8868
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8868 (adapted=198, skipped=1551) — channel allowlist blind spot

### `otrf-empire-shell-rubeus-asktgt-createnetonly` — empire shell rubeus asktgt createnetonly (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** —
- **Hosts/events:** 3 / 263
- **Skip rate:** 0.9267
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** —
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9267 (adapted=263, skipped=3327) — channel allowlist blind spot

### `otrf-empire-smbexec` — smbexec via svcctl (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1021.002
- **Hosts/events:** 3 / 516
- **Skip rate:** 0.9312
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9312 (adapted=516, skipped=6988) — channel allowlist blind spot

### `otrf-empire-uac-shellapi-fodhelper` — empire uac shellapi fodhelper (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** —
- **Hosts/events:** 3 / 324
- **Skip rate:** 0.9217
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** workstation5
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9217 (adapted=324, skipped=3815) — channel allowlist blind spot

### `otrf-empire-wmi-event-persist` — WMI local event subscription (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1546.003
- **Hosts/events:** 3 / 1897
- **Skip rate:** 0.9763
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation5
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9763 (adapted=1897, skipped=77999) — channel allowlist blind spot

### `otrf-empire-wmi-exec` — WMI IWbemServices ExecMethod (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1047
- **Hosts/events:** 3 / 641
- **Skip rate:** 0.8996
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation5, workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8996 (adapted=641, skipped=5742) — channel allowlist blind spot

### `otrf-empire-wmic-add-user-backdoor` — empire wmic add user backdoor (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** —
- **Hosts/events:** 3 / 411
- **Skip rate:** 0.9665
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9665 (adapted=411, skipped=11867) — channel allowlist blind spot

### `otrf-empire-wmic-add-user-backdoor-2` — empire wmic add user backdoor (Empire)

- **Verdict:** `FUSION_HELD`
- **Techniques:** —
- **Hosts/events:** 3 / 411
- **Skip rate:** 0.9665
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9665 (adapted=411, skipped=11867) — channel allowlist blind spot

### `otrf-goldensaml-windows` — Golden SAML ADFS mail-access — Windows host events (Golden SAML / ADFS)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1606.002, T1552
- **Hosts/events:** 2 / 29
- **Skip rate:** 0.2368
- **Corr bridge hosts:** adfs01, dc01
- **Q dry-run:** —
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

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

### `otrf-msf-record-mic` — msf record mic (Metasploit)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** —
- **Hosts/events:** 3 / 232
- **Skip rate:** 0.9626
- **Corr bridge hosts:** mordordc, workstation6
- **Q dry-run:** workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9626 (adapted=232, skipped=5970) — channel allowlist blind spot

### `otrf-ntdsutil-ntds-dit` — ntdsutil NTDS.dit dump (native)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** T1003.003
- **Hosts/events:** 1 / 285
- **Skip rate:** 0.9745
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9745 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9745 (adapted=285, skipped=10899) — channel allowlist blind spot

### `otrf-proxylogon-ssrf-rce-poc` — proxylogon ssrf rce poc (native)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** —
- **Hosts/events:** 1 / 296
- **Skip rate:** 0.9718
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9718 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9718 (adapted=296, skipped=10191) — channel allowlist blind spot

### `otrf-psh-python-webserver` — psh python webserver (native)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** —
- **Hosts/events:** 1 / 8
- **Skip rate:** 0.9967
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9967 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9967 (adapted=8, skipped=2387) — channel allowlist blind spot

### `otrf-purplesharp-ad-playbook-i` — PurpleSharp AD playbook I (multi-step) (PurpleSharp)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1021, T1078, T1087
- **Hosts/events:** 4 / 780
- **Skip rate:** 0.97
- **Corr bridge hosts:** WEC, mordordc, workstation5, workstation6, workstation7
- **Q dry-run:** workstation5
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.97 (adapted=780, skipped=25213) — channel allowlist blind spot

### `otrf-schtask-create` — Remote scheduled task create (native)

- **Verdict:** `FUSION_HELD`
- **Techniques:** T1053.005, T1021
- **Hosts/events:** 2 / 35
- **Skip rate:** 0.9664
- **Corr bridge hosts:** workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9664 (adapted=35, skipped=1006) — channel allowlist blind spot

### `otrf-schtask-modification` — schtask modification (native)

- **Verdict:** `FUSION_HELD`
- **Techniques:** —
- **Hosts/events:** 2 / 46
- **Skip rate:** 0.9827
- **Corr bridge hosts:** workstation5, workstation6
- **Q dry-run:** workstation6
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9827 (adapted=46, skipped=2611) — channel allowlist blind spot


## Honesty

- Authorship: OTRF / MITRE ATT&CK Evals Caldera — **external**.
- Observational metrics (no Corvex-authored ground-truth F1).
- Sanitized JSONL drops CommandLine/ScriptBlockText (Defender PUA).
- `claim_allowed` stays false.

## Reproduce

```bash
python scripts/fetch_opensource_corpora.py --full
python scripts/run_opensource_attack_eval.py
```

