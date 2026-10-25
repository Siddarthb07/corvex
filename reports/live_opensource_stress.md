# Live open-source stress (laptop)

Corvex correlator + dash kept running while OTRF attack captures were **replayed** into `runs/live-oss-stress/`. Not live malware execution.
**claim_allowed=False** · mode=`offline_lab_replay_into_live_correlator`

- Attacks streamed: **56**
- Wall: **675.1844s**
- Catch rollup: `{"CAUGHT": 20, "SINGLE_HOST_BATCH": 17, "ALREADY_COVERED": 19}`
- Dash: `http://127.0.0.1:8765/`
- Sensor sample: `{"ok": false, "returncode": 2, "stdout_tail": "producer prod-a not enrolled for host cyborg_1\n", "stderr_tail": ""}`

## Scoreboard

| # | Attack | Tool | Family | Hosts | Events | Catch | Detail |
|---|--------|------|--------|-------|--------|-------|--------|
| 1 | ATT&CK Evals Round 2 APT29 day1 (full mult | MITRE ATT&CK Evals R2 (manual) | compound_apt29 | 4 | 10980 | **CAUGHT** | multi-host camps 0->4; new bridge hosts=['nashua', 'newyork', 'scranto |
| 2 | ATT&CK Evals Round 2 APT29 day2 (full mult | MITRE ATT&CK Evals R2 (manual) | compound_apt29 | 4 | 67693 | **CAUGHT** | multi-host camps 4->8; new bridge hosts=— |
| 3 | ATT&CK Evals Round 1 APT3 day1 (full scena | Caldera (MITRE ATT&CK Evals R1) | compound_apt3 | 5 | 14423 | **CAUGHT** | multi-host camps 8->15; new bridge hosts=['acct001', 'file001', 'hfdc0 |
| 4 | Empire APT3 multi-day compound | Empire (OTRF APT3 compound) | compound_apt3 | 1 | 7571 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 5 | Golden SAML ADFS mail-access — Windows hos | Golden SAML / ADFS | identity_federation | 2 | 29 | **CAUGHT** | multi-host camps 15->17; new bridge hosts=['adfs01', 'dc01'] |
| 6 | Log4Shell JNDI exploit — Security auditing | Log4Shell CVE-2021-44228 | exploit_cve | 1 | 5 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 7 | Log4Shell JNDI exploit — Sysmon host telem | Log4Shell CVE-2021-44228 | exploit_cve | 1 | 9 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 8 | LSASS campaign: comsvcs MiniDump | Metasploit/comsvcs | credential_dump_campaign | 1 | 1158 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 9 | LSASS campaign: Outflank Dumpert (syscalls | Metasploit/Outflank Dumpert | credential_dump_campaign | 1 | 1379 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 10 | LSASS campaign: Mimikatz logonpasswords me | Metasploit | credential_dump_campaign | 1 | 1238 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 11 | LSASS campaign: NanoDump (evasive) | Metasploit/NanoDump | credential_dump_campaign | 1 | 1112 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 12 | LSASS campaign: Out-Minidump PowerShell | Metasploit/Out-Minidump | credential_dump_campaign | 1 | 1209 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 13 | LSASS campaign: ProcDump LSASS memory dump | Metasploit/ProcDump | credential_dump_campaign | 1 | 1076 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 14 | LSASS campaign: SharpDump | Metasploit/SharpDump | credential_dump_campaign | 1 | 1573 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 15 | DCOM Excel4Macro (allowed) | Covenant | lateral_movement | 3 | 290 | **CAUGHT** | multi-host camps 17->20; new bridge hosts=['mordordc', 'workstation5', |
| 16 | covenant dcom iertutil dll hijack | Covenant | lateral_movement | 3 | 548 | **CAUGHT** | multi-host camps 20->22; new bridge hosts=— |
| 17 | covenant dcom registerxll | Covenant | lateral_movement | 3 | 362 | **CAUGHT** | multi-host camps 22->23; new bridge hosts=— |
| 18 | COM/WSMAN automation | Covenant | lateral_movement | 3 | 87 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 19 | PS remoting command | Covenant | lateral_movement | 3 | 209 | **CAUGHT** | multi-host camps 23->26; new bridge hosts=— |
| 20 | PS remoting Grunt implant | Covenant | lateral_movement | 5 | 1069 | **CAUGHT** | multi-host camps 26->29; new bridge hosts=— |
| 21 | covenant sharpsc create dcerpc smb svcctl | Covenant | lateral_movement | 3 | 260 | **CAUGHT** | multi-host camps 29->31; new bridge hosts=— |
| 22 | covenant sharpsc start dcerpc smb svcctl | Covenant | lateral_movement | 3 | 336 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 23 | SharpWMI create via DCERPC | Covenant | lateral_movement | 3 | 184 | **CAUGHT** | multi-host camps 31->33; new bridge hosts=— |
| 24 | SMB copy CreateRequest | Covenant | lateral_movement | 3 | 39 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 25 | WMI remote event subscription (ActiveScrip | Covenant | lateral_movement | 3 | 300 | **CAUGHT** | multi-host camps 33->36; new bridge hosts=— |
| 26 | WMI wbemcomn.dll hijack | Covenant | lateral_movement | 3 | 418 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 27 | DCOM ShellWindows stager | Empire | lateral_movement | 3 | 521 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 28 | MSBuild via WMI/SMB | Empire | lateral_movement | 3 | 437 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 29 | PsExec / svcctl remote service | Empire | lateral_movement | 3 | 462 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 30 | PowerShell remoting stager | Empire | lateral_movement | 3 | 245 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 31 | Remote service DLL hijack | Empire | lateral_movement | 3 | 920 | **CAUGHT** | multi-host camps 36->38; new bridge hosts=— |
| 32 | smbexec via svcctl | Empire | lateral_movement | 3 | 516 | **CAUGHT** | multi-host camps 38->39; new bridge hosts=— |
| 33 | WMI IWbemServices ExecMethod | Empire | lateral_movement | 3 | 641 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 34 | empire wmic add user backdoor | Empire | lateral_movement | 3 | 411 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 35 | schtask modification | native | lateral_movement | 2 | 46 | **CAUGHT** | multi-host camps 39->40; new bridge hosts=— |
| 36 | cmd dumping ntds dit file volume shadow co | native | credential_access | 1 | 612 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 37 | cmd seatbelt group user | native | discovery | 1 | 3 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 38 | cmd service mod fax | native | privilege_escalation | 1 | 6 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 39 | cmd sharpview pcre net | native | execution | 1 | 8 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 40 | empire launcher vbs | Empire | execution | 3 | 147 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 41 | empire mimikatz backupkeys dcerpc smb lsar | Empire | credential_access | 4 | 3544 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 42 | empire mimikatz extract keys | Empire | credential_access | 3 | 3586 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 43 | empire mimikatz lsadump patch | Empire | credential_access | 3 | 2774 | **CAUGHT** | multi-host camps 40->41; new bridge hosts=— |
| 44 | empire ninjacopy dumping ntds dit file | Empire | credential_access | 1 | 1221 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 45 | empire persistence registry modification r | Empire | persistence | 3 | 1825 | **CAUGHT** | multi-host camps 41->42; new bridge hosts=— |
| 46 | empire powerview ldap ntsecuritydescriptor | Empire | defense_evasion | 3 | 3052 | **CAUGHT** | multi-host camps 42->45; new bridge hosts=— |
| 47 | empire psinject PEinjection | Empire | defense_evasion | 3 | 2302 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 48 | empire schtasks creation standard user | Empire | persistence | 3 | 246 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 49 | empire shell rpc samr smb group domain adm | Empire | discovery | 3 | 198 | **CAUGHT** | multi-host camps 45->46; new bridge hosts=— |
| 50 | empire shell rubeus asktgt createnetonly | Empire | credential_access | 3 | 263 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 51 | empire uac shellapi fodhelper | Empire | privilege_escalation | 3 | 324 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 52 | empire wmic add user backdoor | Empire | defense_evasion | 3 | 411 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 53 | msf record mic | Metasploit | collection | 3 | 232 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 54 | proxylogon ssrf rce poc | native | persistence | 1 | 296 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 55 | psh python webserver | native | execution | 1 | 8 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 56 | PurpleSharp AD playbook I (multi-step) | PurpleSharp | playbook | 4 | 780 | **CAUGHT** | multi-host camps 46->55; new bridge hosts=['workstation7'] |

## Honesty

- Authorship: OTRF / MITRE — external captures.
- Laptop role: correlator process + optional Stage B sensor sample.
- Quarantine: dry_run only (`CORVEX_CONTAIN=0`).
- Does **not** prove enterprise detection or claim_allowed.

## Reproduce

```bash
python scripts/fetch_opensource_corpora.py --live-stress
python scripts/run_live_opensource_stress.py --dash
```

