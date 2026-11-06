# Open-source attacks used (inventory)

Every corpus scored in this eval. Authorship = OTRF / MITRE.

Generated: **2026-11-06T09:29:22Z** | N=**76**

| # | ID | Attack | Tool | ATT&CK / techniques | Family | Verdict | Breaks? |
|---|----|--------|------|---------------------|--------|---------|---------|
| 1 | `otrf-apt29-day1` | ATT&CK Evals Round 2 APT29 day1 (full multi-host) | MITRE ATT&CK Evals R2 (manual) | G0016, APT29, CozyBear | compound_apt29 | **ERROR** | yes |
| 2 | `otrf-apt29-day2` | ATT&CK Evals Round 2 APT29 day2 (full multi-host) | MITRE ATT&CK Evals R2 (manual) | G0016, APT29, CozyBear | compound_apt29 | **ERROR** | yes |
| 3 | `otrf-caldera-apt3-day1` | ATT&CK Evals Round 1 APT3 day1 (full scenario) | Caldera (MITRE ATT&CK Evals R1) | G0022, APT3 | compound_apt3 | **FUSION_HELD** | yes |
| 4 | `otrf-cmd-dumping-ntds-dit-file-volume-shadow-copy` | cmd dumping ntds dit file volume shadow copy | native | — | credential_access | **SINGLE_HOST** | yes |
| 5 | `otrf-cmd-seatbelt-group-user` | cmd seatbelt group user | native | — | discovery | **SINGLE_HOST** | yes |
| 6 | `otrf-cmd-service-mod-fax` | cmd service mod fax | native | — | privilege_escalation | **SINGLE_HOST** | yes |
| 7 | `otrf-cmd-sharpview-pcre-net` | cmd sharpview pcre net | native | — | execution | **SINGLE_HOST** | yes |
| 8 | `otrf-covenant-dcom-excel4` | DCOM Excel4Macro (allowed) | Covenant | T1021.003, T1137.001 | lateral_movement | **FUSION_HELD** | yes |
| 9 | `otrf-covenant-dcom-iertutil-dll-hijack` | covenant dcom iertutil dll hijack | Covenant | — | lateral_movement | **FUSION_HELD** | yes |
| 10 | `otrf-covenant-dcom-registerxll` | covenant dcom registerxll | Covenant | — | lateral_movement | **FUSION_HELD** | yes |
| 11 | `otrf-covenant-dcom-wsman` | COM/WSMAN automation | Covenant | T1021.003, T1021.006 | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 12 | `otrf-covenant-dcsync` | DCSync DsGetNCChanges | Covenant | T1003.006 | credential_access | **FUSION_HELD** | yes |
| 13 | `otrf-covenant-installutil` | InstallUtil LOLBAS | Covenant | T1218.004 | defense_evasion | **FUSION_HELD** | yes |
| 14 | `otrf-covenant-ldap-domain-admins` | LDAP search Domain Admins | Covenant | T1069.002, T1087.002 | discovery | **MULTI_HOST_NO_LIFT** | yes |
| 15 | `otrf-covenant-psremoting` | PS remoting command | Covenant | T1021.006 | lateral_movement | **FUSION_HELD** | yes |
| 16 | `otrf-covenant-psremoting-grunt` | PS remoting Grunt implant | Covenant | T1021.006 | lateral_movement | **FUSION_HELD** | no |
| 17 | `otrf-covenant-sharpsc-create-dcerpc-smb-svcctl` | covenant sharpsc create dcerpc smb svcctl | Covenant | — | lateral_movement | **FUSION_HELD** | yes |
| 18 | `otrf-covenant-sharpsc-start-dcerpc-smb-svcctl` | covenant sharpsc start dcerpc smb svcctl | Covenant | — | lateral_movement | **MULTI_HOST_NO_LIFT** | yes |
| 19 | `otrf-covenant-sharpwmi` | SharpWMI create via DCERPC | Covenant | T1047 | lateral_movement | **FUSION_HELD** | yes |
| 20 | `otrf-covenant-smb-copy` | SMB copy CreateRequest | Covenant | T1021.002, T1570 | lateral_movement | **FUSION_HELD** | yes |
| 21 | `otrf-covenant-wmi-event-sub` | WMI remote event subscription (ActiveScript) | Covenant | T1047, T1546.003 | lateral_movement | **FUSION_HELD** | yes |
| 22 | `otrf-covenant-wmi-hijack` | WMI wbemcomn.dll hijack | Covenant | T1047, T1574.001 | lateral_movement | **FUSION_HELD** | yes |
| 23 | `otrf-empire-apt3` | Empire APT3 multi-day compound | Empire (OTRF APT3 compound) | G0022, APT3 | compound_apt3 | **ERROR** | yes |
| 24 | `otrf-empire-dcom-shellwindows` | DCOM ShellWindows stager | Empire | T1021.003 | lateral_movement | **FUSION_HELD** | yes |
| 25 | `otrf-empire-dcsync` | DCSync DsGetNCChanges | Empire | T1003.006 | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 26 | `otrf-empire-dll-inject` | LoadLibrary CreateRemoteThread inject | Empire | T1055.001 | defense_evasion | **BLIND** | yes |
| 27 | `otrf-empire-find-localadmin` | Find local admin via OpenSCManager | Empire | T1069.001, T1018 | discovery | **FUSION_HELD** | no |
| 28 | `otrf-empire-launcher-vbs` | empire launcher vbs | Empire | — | execution | **FUSION_HELD** | yes |
| 29 | `otrf-empire-mimikatz-backupkeys-dcerpc-smb-lsarpc` | empire mimikatz backupkeys dcerpc smb lsarpc | Empire | — | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 30 | `otrf-empire-mimikatz-extract-keys` | empire mimikatz extract keys | Empire | — | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 31 | `otrf-empire-mimikatz-logonpasswords` | Mimikatz sekurlsa::logonpasswords | Empire/Mimikatz | T1003.001 | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 32 | `otrf-empire-mimikatz-lsadump-patch` | empire mimikatz lsadump patch | Empire | — | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 33 | `otrf-empire-mimikatz-sam` | Mimikatz SAM access | Empire/Mimikatz | T1003.002 | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 34 | `otrf-empire-msbuild-wmi-smb` | MSBuild via WMI/SMB | Empire | T1047, T1127.001 | lateral_movement | **FUSION_HELD** | yes |
| 35 | `otrf-empire-netsession` | NetSessEnum session enum | Empire | T1049 | discovery | **MULTI_HOST_NO_LIFT** | yes |
| 36 | `otrf-empire-ninjacopy-dumping-ntds-dit-file` | empire ninjacopy dumping ntds dit file | Empire | — | credential_access | **SINGLE_HOST** | yes |
| 37 | `otrf-empire-over-pth` | Over-PTH / LSASS patch | Empire | T1550.002, T1003.001 | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 38 | `otrf-empire-persistence-registry-modification-run-keys-` | empire persistence registry modification run keys standard user | Empire | — | persistence | **FUSION_HELD** | yes |
| 39 | `otrf-empire-powerview-ldap-ntsecuritydescriptor` | empire powerview ldap ntsecuritydescriptor | Empire | — | defense_evasion | **FUSION_HELD** | no |
| 40 | `otrf-empire-psexec` | PsExec / svcctl remote service | Empire | T1021.002, T1570 | lateral_movement | **FUSION_HELD** | yes |
| 41 | `otrf-empire-psinject-injection` | empire psinject PEinjection | Empire | — | defense_evasion | **MULTI_HOST_NO_LIFT** | yes |
| 42 | `otrf-empire-psremoting` | PowerShell remoting stager | Empire | T1021.006 | lateral_movement | **FUSION_HELD** | yes |
| 43 | `otrf-empire-regsvr32-sct` | regsvr32 SCT launcher | Empire | T1218.010 | defense_evasion | **FUSION_HELD** | yes |
| 44 | `otrf-empire-rubeus-asktgt` | Rubeus asktgt + PTT | Empire/Rubeus | T1558.001, T1550.003 | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 45 | `otrf-empire-run-keys` | Registry Run keys (elevated) | Empire | T1547.001 | persistence | **FUSION_HELD** | no |
| 46 | `otrf-empire-samr-enum-users` | SAMR EnumDomainUsers | Empire | T1087.002 | discovery | **MULTI_HOST_NO_LIFT** | yes |
| 47 | `otrf-empire-schtasks-creation-standard-user` | empire schtasks creation standard user | Empire | — | persistence | **FUSION_HELD** | no |
| 48 | `otrf-empire-schtasks-elevated` | Schtasks create (elevated) | Empire | T1053.005 | persistence | **FUSION_HELD** | yes |
| 49 | `otrf-empire-service-dll-hijack` | Remote service DLL hijack | Empire | T1574.001, T1543.003 | lateral_movement | **FUSION_HELD** | yes |
| 50 | `otrf-empire-shell-net-local-users` | empire shell net local users | Empire | — | discovery | **ERROR** | yes |
| 51 | `otrf-empire-shell-net-localgroup-administrators` | empire shell net localgroup administrators | Empire | — | discovery | **ERROR** | yes |
| 52 | `otrf-empire-shell-rpc-samr-smb-group-domain-admins-stan` | empire shell rpc samr smb group domain admins standard user | Empire | — | discovery | **FUSION_HELD** | yes |
| 53 | `otrf-empire-shell-rubeus-asktgt-createnetonly` | empire shell rubeus asktgt createnetonly | Empire | — | credential_access | **MULTI_HOST_NO_LIFT** | yes |
| 54 | `otrf-empire-smbexec` | smbexec via svcctl | Empire | T1021.002 | lateral_movement | **FUSION_HELD** | yes |
| 55 | `otrf-empire-uac-shellapi-fodhelper` | empire uac shellapi fodhelper | Empire | — | privilege_escalation | **MULTI_HOST_NO_LIFT** | yes |
| 56 | `otrf-empire-wmi-event-persist` | WMI local event subscription | Empire | T1546.003 | persistence | **FUSION_HELD** | yes |
| 57 | `otrf-empire-wmi-exec` | WMI IWbemServices ExecMethod | Empire | T1047 | lateral_movement | **FUSION_HELD** | yes |
| 58 | `otrf-empire-wmic-add-user-backdoor` | empire wmic add user backdoor | Empire | — | lateral_movement | **FUSION_HELD** | yes |
| 59 | `otrf-empire-wmic-add-user-backdoor-2` | empire wmic add user backdoor | Empire | — | defense_evasion | **FUSION_HELD** | yes |
| 60 | `otrf-goldensaml-windows` | Golden SAML ADFS mail-access — Windows host events | Golden SAML / ADFS | T1606.002, T1552 | identity_federation | **MULTI_HOST_NO_LIFT** | yes |
| 61 | `otrf-log4shell-security` | Log4Shell JNDI exploit — Security auditing host | Log4Shell CVE-2021-44228 | T1190, T1059.007 | exploit_cve | **SINGLE_HOST** | yes |
| 62 | `otrf-log4shell-sysmon` | Log4Shell JNDI exploit — Sysmon host telemetry | Log4Shell CVE-2021-44228 | T1190, T1059.007 | exploit_cve | **SINGLE_HOST** | yes |
| 63 | `otrf-lsass-metasploit-comsvcs` | LSASS campaign: comsvcs MiniDump | Metasploit/comsvcs | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |
| 64 | `otrf-lsass-metasploit-dumpert` | LSASS campaign: Outflank Dumpert (syscalls) | Metasploit/Outflank Dumpert | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |
| 65 | `otrf-lsass-metasploit-logonpasswords` | LSASS campaign: Mimikatz logonpasswords memory dump | Metasploit | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |
| 66 | `otrf-lsass-metasploit-nanodump` | LSASS campaign: NanoDump (evasive) | Metasploit/NanoDump | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |
| 67 | `otrf-lsass-metasploit-out-minidump` | LSASS campaign: Out-Minidump PowerShell | Metasploit/Out-Minidump | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |
| 68 | `otrf-lsass-metasploit-procdump` | LSASS campaign: ProcDump LSASS memory dump | Metasploit/ProcDump | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |
| 69 | `otrf-lsass-metasploit-sharpdump` | LSASS campaign: SharpDump | Metasploit/SharpDump | T1003.001 | credential_dump_campaign | **SINGLE_HOST** | yes |
| 70 | `otrf-msf-record-mic` | msf record mic | Metasploit | — | collection | **MULTI_HOST_NO_LIFT** | yes |
| 71 | `otrf-ntdsutil-ntds-dit` | ntdsutil NTDS.dit dump | native | T1003.003 | credential_access | **SINGLE_HOST** | yes |
| 72 | `otrf-proxylogon-ssrf-rce-poc` | proxylogon ssrf rce poc | native | — | persistence | **SINGLE_HOST** | yes |
| 73 | `otrf-psh-python-webserver` | psh python webserver | native | — | execution | **SINGLE_HOST** | yes |
| 74 | `otrf-purplesharp-ad-playbook-i` | PurpleSharp AD playbook I (multi-step) | PurpleSharp | T1021, T1078, T1087 | playbook | **FUSION_HELD** | yes |
| 75 | `otrf-schtask-create` | Remote scheduled task create | native | T1053.005, T1021 | persistence_lateral | **FUSION_HELD** | yes |
| 76 | `otrf-schtask-modification` | schtask modification | native | — | lateral_movement | **FUSION_HELD** | yes |

## By tool

| Tool | Verdicts |
|------|----------|
| Caldera (MITRE ATT&CK Evals R1) | FUSION_HELD=1 |
| Covenant | FUSION_HELD=12, MULTI_HOST_NO_LIFT=3 |
| Empire | BLIND=1, ERROR=2, FUSION_HELD=19, MULTI_HOST_NO_LIFT=10, SINGLE_HOST=1 |
| Empire (OTRF APT3 compound) | ERROR=1 |
| Empire/Mimikatz | MULTI_HOST_NO_LIFT=2 |
| Empire/Rubeus | MULTI_HOST_NO_LIFT=1 |
| Golden SAML / ADFS | MULTI_HOST_NO_LIFT=1 |
| Log4Shell CVE-2021-44228 | SINGLE_HOST=2 |
| MITRE ATT&CK Evals R2 (manual) | ERROR=2 |
| Metasploit | MULTI_HOST_NO_LIFT=1, SINGLE_HOST=1 |
| Metasploit/NanoDump | SINGLE_HOST=1 |
| Metasploit/Out-Minidump | SINGLE_HOST=1 |
| Metasploit/Outflank Dumpert | SINGLE_HOST=1 |
| Metasploit/ProcDump | SINGLE_HOST=1 |
| Metasploit/SharpDump | SINGLE_HOST=1 |
| Metasploit/comsvcs | SINGLE_HOST=1 |
| PurpleSharp | FUSION_HELD=1 |
| native | FUSION_HELD=2, SINGLE_HOST=7 |

## By ATT&CK family

| Family | Verdicts |
|--------|----------|
| collection | MULTI_HOST_NO_LIFT=1 |
| compound_apt29 | ERROR=2 |
| compound_apt3 | ERROR=1, FUSION_HELD=1 |
| credential_access | FUSION_HELD=1, MULTI_HOST_NO_LIFT=9, SINGLE_HOST=3 |
| credential_dump_campaign | SINGLE_HOST=7 |
| defense_evasion | BLIND=1, FUSION_HELD=4, MULTI_HOST_NO_LIFT=1 |
| discovery | ERROR=2, FUSION_HELD=2, MULTI_HOST_NO_LIFT=3, SINGLE_HOST=1 |
| execution | FUSION_HELD=1, SINGLE_HOST=2 |
| exploit_cve | SINGLE_HOST=2 |
| identity_federation | MULTI_HOST_NO_LIFT=1 |
| lateral_movement | FUSION_HELD=19, MULTI_HOST_NO_LIFT=2 |
| persistence | FUSION_HELD=5, SINGLE_HOST=1 |
| persistence_lateral | FUSION_HELD=1 |
| playbook | FUSION_HELD=1 |
| privilege_escalation | MULTI_HOST_NO_LIFT=1, SINGLE_HOST=1 |

## Upstream

- https://github.com/OTRF/Security-Datasets
- APT3 / APT29: MITRE ATT&CK Evals via Caldera / Empire / manual compounds
- LSASS: Metasploit dump technique variants (OTRF compound campaigns)

