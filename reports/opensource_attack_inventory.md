# Open-source attacks used (inventory)

Every corpus scored in the latest open-source eval. Authorship = OTRF / MITRE.

Generated: **2026-10-23T17:00:50Z** | N=**36**

| # | ID | Attack | Tool | ATT&CK / techniques | Family | Verdict | Breaks? |
|---|----|--------|------|---------------------|--------|---------|---------|
| 1 | `otrf-caldera-apt3-day1` | ATT&CK Evals Round 1 APT3 day1 (full scenario) | Caldera (MITRE ATT&CK Evals R1) | G0022, APT3 | compound_apt3 | **MULTI_HOST_NO_LIFT** | yes |
| 2 | `otrf-covenant-dcom-excel4` | DCOM Excel4Macro (allowed) | Covenant | T1021.003, T1137.001 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 3 | `otrf-covenant-dcom-wsman` | COM/WSMAN automation | Covenant | T1021.003, T1021.006 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 4 | `otrf-covenant-dcsync` | DCSync DsGetNCChanges | Covenant | T1003.006 | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 5 | `otrf-covenant-installutil` | InstallUtil LOLBAS | Covenant | T1218.004 | defense_evasion | **MULTI_HOST_NO_LIFT** | yes |
| 6 | `otrf-covenant-ldap-domain-admins` | LDAP search Domain Admins | Covenant | T1069.002, T1087.002 | discovery | **MULTI_HOST_NO_LIFT** | yes |
| 7 | `otrf-covenant-psremoting` | PS remoting command | Covenant | T1021.006 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 8 | `otrf-covenant-psremoting-grunt` | PS remoting Grunt implant | Covenant | T1021.006 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 9 | `otrf-covenant-sharpwmi` | SharpWMI create via DCERPC | Covenant | T1047 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 10 | `otrf-covenant-smb-copy` | SMB copy CreateRequest | Covenant | T1021.002, T1570 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 11 | `otrf-covenant-wmi-event-sub` | WMI remote event subscription (ActiveScript) | Covenant | T1047, T1546.003 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 12 | `otrf-covenant-wmi-hijack` | WMI wbemcomn.dll hijack | Covenant | T1047, T1574.001 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 13 | `otrf-empire-apt3` | Empire APT3 multi-day compound | Empire (OTRF APT3 compound) | G0022, APT3 | compound_apt3 | **SINGLE_HOST** | yes |
| 14 | `otrf-empire-dcom-shellwindows` | DCOM ShellWindows stager | Empire | T1021.003 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 15 | `otrf-empire-dcsync` | DCSync DsGetNCChanges | Empire | T1003.006 | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 16 | `otrf-empire-dll-inject` | LoadLibrary CreateRemoteThread inject | Empire | T1055.001 | defense_evasion | **MULTI_HOST_NO_LIFT** | yes |
| 17 | `otrf-empire-find-localadmin` | Find local admin via OpenSCManager | Empire | T1069.001, T1018 | discovery | **MULTI_HOST_NO_LIFT** | yes |
| 18 | `otrf-empire-mimikatz-logonpasswords` | Mimikatz sekurlsa::logonpasswords | Empire/Mimikatz | T1003.001 | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 19 | `otrf-empire-mimikatz-sam` | Mimikatz SAM access | Empire/Mimikatz | T1003.002 | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 20 | `otrf-empire-msbuild-wmi-smb` | MSBuild via WMI/SMB | Empire | T1047, T1127.001 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 21 | `otrf-empire-netsession` | NetSessEnum session enum | Empire | T1049 | discovery | **MULTI_HOST_NO_LIFT** | yes |
| 22 | `otrf-empire-over-pth` | Over-PTH / LSASS patch | Empire | T1550.002, T1003.001 | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 23 | `otrf-empire-psexec` | PsExec / svcctl remote service | Empire | T1021.002, T1570 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 24 | `otrf-empire-psremoting` | PowerShell remoting stager | Empire | T1021.006 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 25 | `otrf-empire-regsvr32-sct` | regsvr32 SCT launcher | Empire | T1218.010 | defense_evasion | **MULTI_HOST_NO_LIFT** | yes |
| 26 | `otrf-empire-rubeus-asktgt` | Rubeus asktgt + PTT | Empire/Rubeus | T1558.001, T1550.003 | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 27 | `otrf-empire-run-keys` | Registry Run keys (elevated) | Empire | T1547.001 | persistence | **MULTI_HOST_NO_LIFT** | yes |
| 28 | `otrf-empire-samr-enum-users` | SAMR EnumDomainUsers | Empire | T1087.002 | discovery | **MULTI_HOST_NO_LIFT** | yes |
| 29 | `otrf-empire-schtasks-elevated` | Schtasks create (elevated) | Empire | T1053.005 | persistence | **MULTI_HOST_NO_LIFT** | yes |
| 30 | `otrf-empire-service-dll-hijack` | Remote service DLL hijack | Empire | T1574.001, T1543.003 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 31 | `otrf-empire-smbexec` | smbexec via svcctl | Empire | T1021.002 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 32 | `otrf-empire-wmi-event-persist` | WMI local event subscription | Empire | T1546.003 | persistence | **MULTI_HOST_NO_LIFT** | yes |
| 33 | `otrf-empire-wmi-exec` | WMI IWbemServices ExecMethod | Empire | T1047 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 34 | `otrf-ntdsutil-ntds-dit` | ntdsutil NTDS.dit dump | native | T1003.003 | credential_access | **SINGLE_HOST** | yes |
| 35 | `otrf-purplesharp-ad-playbook-i` | PurpleSharp AD playbook I (multi-step) | PurpleSharp | T1021, T1078, T1087 | playbook | **MULTI_HOST_NO_LIFT** | yes |
| 36 | `otrf-schtask-create` | Remote scheduled task create | native | T1053.005, T1021 | persistence_lateral | **MULTI_HOST_NO_LIFT** | yes |

## By tool

| Tool | Verdicts |
|------|----------|
| Caldera (MITRE ATT&CK Evals R1) | MULTI_HOST_NO_LIFT=1 |
| Covenant | MULTI_HOST_NO_LIFT=11 |
| Empire | MULTI_HOST_NO_LIFT=17 |
| Empire (OTRF APT3 compound) | SINGLE_HOST=1 |
| Empire/Mimikatz | MULTI_HOST_NO_LIFT=2 |
| Empire/Rubeus | MULTI_HOST_NO_LIFT=1 |
| PurpleSharp | MULTI_HOST_NO_LIFT=1 |
| native | MULTI_HOST_NO_LIFT=1, SINGLE_HOST=1 |

## By ATT&CK family

| Family | Verdicts |
|--------|----------|
| compound_apt3 | MULTI_HOST_NO_LIFT=1, SINGLE_HOST=1 |
| credential_access | MULTI_HOST_NO_LIFT=6, SINGLE_HOST=1 |
| defense_evasion | MULTI_HOST_NO_LIFT=3 |
| discovery | MULTI_HOST_NO_LIFT=4 |
| lateral_movement | MULTI_HOST_NO_LIFT=15 |
| persistence | MULTI_HOST_NO_LIFT=3 |
| persistence_lateral | MULTI_HOST_NO_LIFT=1 |
| playbook | MULTI_HOST_NO_LIFT=1 |

## Upstream

- https://github.com/OTRF/Security-Datasets
- APT3: MITRE ATT&CK Evals Round 1 via Caldera / Empire compounds

