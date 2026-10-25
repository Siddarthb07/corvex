# Open-source attack eval (OTRF / Security-Datasets)

Externally authored captures. **Not** Corvex-written fleet manifests.
**claim_allowed=False**. Lab purple-team only.

- Corpora scored: **36** | Wall: **16.1703s**
- Catalog: `labs/opensource/catalog.json`
- Attack inventory: [`opensource_attack_inventory.md`](opensource_attack_inventory.md)

## Verdict rollup (observational)

| Label | Count | Meaning |
|-------|-------|---------|
| **MULTI_HOST_NO_LIFT** | 34 | Multi-host present; fusion adds no host-coverage lift |
| **SINGLE_HOST** | 2 | Capture has <2 hosts — fusion not testable |

## Scoreboard

| Attack | Tool | Family | Verdict | Hosts | Events | Lift | Q all? | Breaks |
|--------|------|--------|---------|-------|--------|------|--------|--------|
| ATT&CK Evals Round 1 APT3 day1 (full scenario) | Caldera (MITRE ATT&CK Evals R1) | compound_apt3 | **MULTI_HOST_NO_LIFT** | 5 | 14227 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `G0022,APT3` | | | | | | | | |
| DCOM Excel4Macro (allowed) | Covenant | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 286 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1021.003,T1137.001` | | | | | | | | |
| COM/WSMAN automation | Covenant | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 86 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1021.003,T1021.006` | | | | | | | | |
| DCSync DsGetNCChanges | Covenant | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 107 | -1 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1003.006` | | | | | | | | |
| InstallUtil LOLBAS | Covenant | defense_evasion | **MULTI_HOST_NO_LIFT** | 3 | 90 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1218.004` | | | | | | | | |
| LDAP search Domain Admins | Covenant | discovery | **MULTI_HOST_NO_LIFT** | 3 | 50 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1069.002,T1087.002` | | | | | | | | |
| PS remoting command | Covenant | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 199 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1021.006` | | | | | | | | |
| PS remoting Grunt implant | Covenant | lateral_movement | **MULTI_HOST_NO_LIFT** | 5 | 789 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1021.006` | | | | | | | | |
| SharpWMI create via DCERPC | Covenant | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 180 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1047` | | | | | | | | |
| SMB copy CreateRequest | Covenant | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 33 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1021.002,T1570` | | | | | | | | |
| WMI remote event subscription (ActiveScript) | Covenant | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 293 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1047,T1546.003` | | | | | | | | |
| WMI wbemcomn.dll hijack | Covenant | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 412 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1047,T1574.001` | | | | | | | | |
| Empire APT3 multi-day compound | Empire (OTRF APT3 compound) | compound_apt3 | **SINGLE_HOST** | 1 | 6948 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| ↳ techniques `G0022,APT3` | | | | | | | | |
| DCOM ShellWindows stager | Empire | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 518 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1021.003` | | | | | | | | |
| DCSync DsGetNCChanges | Empire | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 3670 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1003.006` | | | | | | | | |
| LoadLibrary CreateRemoteThread inject | Empire | defense_evasion | **MULTI_HOST_NO_LIFT** | 3 | 2277 | -1 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1055.001` | | | | | | | | |
| Find local admin via OpenSCManager | Empire | discovery | **MULTI_HOST_NO_LIFT** | 3 | 878 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1069.001,T1018` | | | | | | | | |
| Mimikatz sekurlsa::logonpasswords | Empire/Mimikatz | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 2008 | -1 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1003.001` | | | | | | | | |
| Mimikatz SAM access | Empire/Mimikatz | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 3362 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1003.002` | | | | | | | | |
| MSBuild via WMI/SMB | Empire | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 425 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1047,T1127.001` | | | | | | | | |
| NetSessEnum session enum | Empire | discovery | **MULTI_HOST_NO_LIFT** | 3 | 716 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1049` | | | | | | | | |
| Over-PTH / LSASS patch | Empire | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 4078 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1550.002,T1003.001` | | | | | | | | |
| PsExec / svcctl remote service | Empire | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 458 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1021.002,T1570` | | | | | | | | |
| PowerShell remoting stager | Empire | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 243 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1021.006` | | | | | | | | |
| regsvr32 SCT launcher | Empire | defense_evasion | **MULTI_HOST_NO_LIFT** | 2 | 309 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1218.010` | | | | | | | | |
| Rubeus asktgt + PTT | Empire/Rubeus | credential_access | **MULTI_HOST_NO_LIFT** | 3 | 212 | -1 | no | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1558.001,T1550.003` | | | | | | | | |
| Registry Run keys (elevated) | Empire | persistence | **MULTI_HOST_NO_LIFT** | 3 | 309 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1547.001` | | | | | | | | |
| SAMR EnumDomainUsers | Empire | discovery | **MULTI_HOST_NO_LIFT** | 3 | 106 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1087.002` | | | | | | | | |
| Schtasks create (elevated) | Empire | persistence | **MULTI_HOST_NO_LIFT** | 3 | 1656 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1053.005` | | | | | | | | |
| Remote service DLL hijack | Empire | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 904 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1574.001,T1543.003` | | | | | | | | |
| smbexec via svcctl | Empire | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 513 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1021.002` | | | | | | | | |
| WMI local event subscription | Empire | persistence | **MULTI_HOST_NO_LIFT** | 3 | 1831 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1546.003` | | | | | | | | |
| WMI IWbemServices ExecMethod | Empire | lateral_movement | **MULTI_HOST_NO_LIFT** | 3 | 637 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1047` | | | | | | | | |
| ntdsutil NTDS.dit dump | native | credential_access | **SINGLE_HOST** | 1 | 282 | 0 | no | SINGLE_HOST: single-host capture — multi-host fusion not … |
| ↳ techniques `T1003.003` | | | | | | | | |
| PurpleSharp AD playbook I (multi-step) | PurpleSharp | playbook | **MULTI_HOST_NO_LIFT** | 4 | 750 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1021,T1078,T1087` | | | | | | | | |
| Remote scheduled task create | native | persistence_lateral | **MULTI_HOST_NO_LIFT** | 2 | 35 | 0 | yes | FUSION_NO_LIFT: correlator multi-host bridge does not cov… |
| ↳ techniques `T1053.005,T1021` | | | | | | | | |

## Where it breaks (every flagged corpus)

### `otrf-caldera-apt3-day1` — ATT&CK Evals Round 1 APT3 day1 (full scenario) (Caldera (MITRE ATT&CK Evals R1))

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** G0022, APT3
- **Hosts/events:** 5 / 14227
- **Skip rate:** 0.8604
- **Corr bridge hosts:** acct001, file001, hfdc01, hr001, it001
- **Q dry-run:** acct001, file001, hfdc01, hr001, it001
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 5 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8604 (adapted=14227, skipped=87677) — channel allowlist blind spot

### `otrf-covenant-dcom-excel4` — DCOM Excel4Macro (allowed) (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1021.003, T1137.001
- **Hosts/events:** 3 / 286
- **Skip rate:** 0.9648
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9648 (adapted=286, skipped=7835) — channel allowlist blind spot

### `otrf-covenant-dcom-wsman` — COM/WSMAN automation (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1021.003, T1021.006
- **Hosts/events:** 3 / 86
- **Skip rate:** 0.894
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.894 (adapted=86, skipped=725) — channel allowlist blind spot

### `otrf-covenant-dcsync` — DCSync DsGetNCChanges (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1003.006
- **Hosts/events:** 3 / 107
- **Skip rate:** 0.8769
- **Corr bridge hosts:** workstation5, workstation6
- **Q dry-run:** workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8769 (adapted=107, skipped=762) — channel allowlist blind spot

### `otrf-covenant-installutil` — InstallUtil LOLBAS (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1218.004
- **Hosts/events:** 3 / 90
- **Skip rate:** 0.948
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.948 (adapted=90, skipped=1640) — channel allowlist blind spot

### `otrf-covenant-ldap-domain-admins` — LDAP search Domain Admins (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1069.002, T1087.002
- **Hosts/events:** 3 / 50
- **Skip rate:** 0.9192
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9192 (adapted=50, skipped=569) — channel allowlist blind spot

### `otrf-covenant-psremoting` — PS remoting command (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1021.006
- **Hosts/events:** 3 / 199
- **Skip rate:** 0.9535
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9535 (adapted=199, skipped=4085) — channel allowlist blind spot

### `otrf-covenant-psremoting-grunt` — PS remoting Grunt implant (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1021.006
- **Hosts/events:** 5 / 789
- **Skip rate:** 0.8167
- **Corr bridge hosts:** acct001, file001, hfdc01, hr001, it001
- **Q dry-run:** acct001, file001, hfdc01, hr001, it001
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 5 observed hosts

### `otrf-covenant-sharpwmi` — SharpWMI create via DCERPC (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1047
- **Hosts/events:** 3 / 180
- **Skip rate:** 0.9232
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9232 (adapted=180, skipped=2163) — channel allowlist blind spot

### `otrf-covenant-smb-copy` — SMB copy CreateRequest (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1021.002, T1570
- **Hosts/events:** 3 / 33
- **Skip rate:** 0.9348
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9348 (adapted=33, skipped=473) — channel allowlist blind spot

### `otrf-covenant-wmi-event-sub` — WMI remote event subscription (ActiveScript) (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1047, T1546.003
- **Hosts/events:** 3 / 293
- **Skip rate:** 0.9212
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9212 (adapted=293, skipped=3426) — channel allowlist blind spot

### `otrf-covenant-wmi-hijack` — WMI wbemcomn.dll hijack (Covenant)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1047, T1574.001
- **Hosts/events:** 3 / 412
- **Skip rate:** 0.954
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.954 (adapted=412, skipped=8535) — channel allowlist blind spot

### `otrf-empire-apt3` — Empire APT3 multi-day compound (Empire (OTRF APT3 compound))

- **Verdict:** `SINGLE_HOST`
- **Techniques:** G0022, APT3
- **Hosts/events:** 1 / 6948
- **Skip rate:** 0.9429
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9429 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9429 (adapted=6948, skipped=114711) — channel allowlist blind spot

### `otrf-empire-dcom-shellwindows` — DCOM ShellWindows stager (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1021.003
- **Hosts/events:** 3 / 518
- **Skip rate:** 0.9842
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9842 (adapted=518, skipped=32188) — channel allowlist blind spot

### `otrf-empire-dcsync` — DCSync DsGetNCChanges (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1003.006
- **Hosts/events:** 3 / 3670
- **Skip rate:** 0.5665
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts

### `otrf-empire-dll-inject` — LoadLibrary CreateRemoteThread inject (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1055.001
- **Hosts/events:** 3 / 2277
- **Skip rate:** 0.8134
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** mordordc, workstation5
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

### `otrf-empire-find-localadmin` — Find local admin via OpenSCManager (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1069.001, T1018
- **Hosts/events:** 3 / 878
- **Skip rate:** 0.8079
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts

### `otrf-empire-mimikatz-logonpasswords` — Mimikatz sekurlsa::logonpasswords (Empire/Mimikatz)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1003.001
- **Hosts/events:** 3 / 2008
- **Skip rate:** 0.6668
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** mordordc, workstation5
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

### `otrf-empire-mimikatz-sam` — Mimikatz SAM access (Empire/Mimikatz)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1003.002
- **Hosts/events:** 3 / 3362
- **Skip rate:** 0.7278
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts

### `otrf-empire-msbuild-wmi-smb` — MSBuild via WMI/SMB (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1047, T1127.001
- **Hosts/events:** 3 / 425
- **Skip rate:** 0.9068
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9068 (adapted=425, skipped=4134) — channel allowlist blind spot

### `otrf-empire-netsession` — NetSessEnum session enum (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1049
- **Hosts/events:** 3 / 716
- **Skip rate:** 0.8581
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8581 (adapted=716, skipped=4331) — channel allowlist blind spot

### `otrf-empire-over-pth` — Over-PTH / LSASS patch (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1550.002, T1003.001
- **Hosts/events:** 3 / 4078
- **Skip rate:** 0.603
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts

### `otrf-empire-psexec` — PsExec / svcctl remote service (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1021.002, T1570
- **Hosts/events:** 3 / 458
- **Skip rate:** 0.8947
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8947 (adapted=458, skipped=3890) — channel allowlist blind spot

### `otrf-empire-psremoting` — PowerShell remoting stager (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1021.006
- **Hosts/events:** 3 / 243
- **Skip rate:** 0.9114
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9114 (adapted=243, skipped=2501) — channel allowlist blind spot

### `otrf-empire-regsvr32-sct` — regsvr32 SCT launcher (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1218.010
- **Hosts/events:** 2 / 309
- **Skip rate:** 0.8707
- **Corr bridge hosts:** mordordc, workstation5
- **Q dry-run:** mordordc, workstation5
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 2 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8707 (adapted=309, skipped=2081) — channel allowlist blind spot

### `otrf-empire-rubeus-asktgt` — Rubeus asktgt + PTT (Empire/Rubeus)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1558.001, T1550.003
- **Hosts/events:** 3 / 212
- **Skip rate:** 0.8202
- **Corr bridge hosts:** mordordc, workstation6
- **Q dry-run:** mordordc, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only

### `otrf-empire-run-keys` — Registry Run keys (elevated) (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1547.001
- **Hosts/events:** 3 / 309
- **Skip rate:** 0.5297
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts

### `otrf-empire-samr-enum-users` — SAMR EnumDomainUsers (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1087.002
- **Hosts/events:** 3 / 106
- **Skip rate:** 0.8325
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts

### `otrf-empire-schtasks-elevated` — Schtasks create (elevated) (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1053.005
- **Hosts/events:** 3 / 1656
- **Skip rate:** 0.9721
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9721 (adapted=1656, skipped=57743) — channel allowlist blind spot

### `otrf-empire-service-dll-hijack` — Remote service DLL hijack (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1574.001, T1543.003
- **Hosts/events:** 3 / 904
- **Skip rate:** 0.8576
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.8576 (adapted=904, skipped=5445) — channel allowlist blind spot

### `otrf-empire-smbexec` — smbexec via svcctl (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1021.002
- **Hosts/events:** 3 / 513
- **Skip rate:** 0.9316
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9316 (adapted=513, skipped=6991) — channel allowlist blind spot

### `otrf-empire-wmi-event-persist` — WMI local event subscription (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1546.003
- **Hosts/events:** 3 / 1831
- **Skip rate:** 0.9771
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9771 (adapted=1831, skipped=78065) — channel allowlist blind spot

### `otrf-empire-wmi-exec` — WMI IWbemServices ExecMethod (Empire)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1047
- **Hosts/events:** 3 / 637
- **Skip rate:** 0.9002
- **Corr bridge hosts:** mordordc, workstation5, workstation6
- **Q dry-run:** mordordc, workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 3 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9002 (adapted=637, skipped=5746) — channel allowlist blind spot

### `otrf-ntdsutil-ntds-dit` — ntdsutil NTDS.dit dump (native)

- **Verdict:** `SINGLE_HOST`
- **Techniques:** T1003.003
- **Hosts/events:** 1 / 282
- **Skip rate:** 0.9748
- **Corr bridge hosts:** —
- **Q dry-run:** —
- **Break:** SINGLE_HOST: single-host capture — multi-host fusion not testable; adapter skip_rate=0.9748 (most raw events dropped)
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9748 (adapted=282, skipped=10902) — channel allowlist blind spot

### `otrf-purplesharp-ad-playbook-i` — PurpleSharp AD playbook I (multi-step) (PurpleSharp)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1021, T1078, T1087
- **Hosts/events:** 4 / 750
- **Skip rate:** 0.9711
- **Corr bridge hosts:** mordordc, workstation5, workstation6, workstation7
- **Q dry-run:** mordordc, workstation5, workstation6, workstation7
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 4 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9711 (adapted=750, skipped=25243) — channel allowlist blind spot

### `otrf-schtask-create` — Remote scheduled task create (native)

- **Verdict:** `MULTI_HOST_NO_LIFT`
- **Techniques:** T1053.005, T1021
- **Hosts/events:** 2 / 35
- **Skip rate:** 0.9664
- **Corr bridge hosts:** workstation5, workstation6
- **Q dry-run:** workstation5, workstation6
- **Break:** FUSION_NO_LIFT: correlator multi-host bridge does not cover more hosts than detector-only
- **Break:** Q_DRYRUN_ALL_HOSTS: quarantine dry-run proposes all 2 observed hosts
- **Break:** ADAPTER_HEAVY_SKIP: skip_rate=0.9664 (adapted=35, skipped=1006) — channel allowlist blind spot


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

