# Live open-source stress (laptop)

Corvex correlator + dash kept running while OTRF attack captures were **replayed** into `runs/live-oss-stress/`. Not live malware execution.
**claim_allowed=False** · mode=`offline_lab_replay_into_live_correlator`

- Attacks streamed: **53**
- Wall: **108.0983s**
- Catch rollup: `{"CAUGHT": 22, "SINGLE_HOST_BATCH": 16, "ALREADY_COVERED": 15}`
- Dash: `—`
- Sensor sample: `{}`

## Scoreboard

| # | Attack | Tool | Family | Hosts | Events | Catch | Detail |
|---|--------|------|--------|-------|--------|-------|--------|
| 1 | ATT&CK Evals Round 1 APT3 day1 (full scena | Caldera (MITRE ATT&CK Evals R1) | compound_apt3 | 5 | 14423 | **CAUGHT** | multi-host camps 0->1; new bridge hosts=['acct001', 'file001', 'hfdc01 |
| 2 | Golden SAML ADFS mail-access — Windows hos | Golden SAML / ADFS | identity_federation | 2 | 29 | **CAUGHT** | multi-host camps 1->4; new bridge hosts=['adfs01', 'dc01'] |
| 3 | Log4Shell JNDI exploit — Security auditing | Log4Shell CVE-2021-44228 | exploit_cve | 1 | 5 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 4 | Log4Shell JNDI exploit — Sysmon host telem | Log4Shell CVE-2021-44228 | exploit_cve | 1 | 9 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 5 | LSASS campaign: comsvcs MiniDump | Metasploit/comsvcs | credential_dump_campaign | 1 | 1158 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 6 | LSASS campaign: Outflank Dumpert (syscalls | Metasploit/Outflank Dumpert | credential_dump_campaign | 1 | 1379 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 7 | LSASS campaign: Mimikatz logonpasswords me | Metasploit | credential_dump_campaign | 1 | 1238 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 8 | LSASS campaign: NanoDump (evasive) | Metasploit/NanoDump | credential_dump_campaign | 1 | 1112 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 9 | LSASS campaign: Out-Minidump PowerShell | Metasploit/Out-Minidump | credential_dump_campaign | 1 | 1209 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 10 | LSASS campaign: ProcDump LSASS memory dump | Metasploit/ProcDump | credential_dump_campaign | 1 | 1076 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 11 | LSASS campaign: SharpDump | Metasploit/SharpDump | credential_dump_campaign | 1 | 1573 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 12 | DCOM Excel4Macro (allowed) | Covenant | lateral_movement | 3 | 290 | **CAUGHT** | multi-host camps 4->5; new bridge hosts=['mordordc', 'workstation5', ' |
| 13 | covenant dcom iertutil dll hijack | Covenant | lateral_movement | 3 | 548 | **CAUGHT** | multi-host camps 5->7; new bridge hosts=— |
| 14 | covenant dcom registerxll | Covenant | lateral_movement | 3 | 362 | **CAUGHT** | multi-host camps 7->11; new bridge hosts=— |
| 15 | COM/WSMAN automation | Covenant | lateral_movement | 3 | 87 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 16 | PS remoting command | Covenant | lateral_movement | 3 | 209 | **CAUGHT** | multi-host camps 11->14; new bridge hosts=— |
| 17 | PS remoting Grunt implant | Covenant | lateral_movement | 5 | 1069 | **CAUGHT** | multi-host camps 14->15; new bridge hosts=— |
| 18 | covenant sharpsc create dcerpc smb svcctl | Covenant | lateral_movement | 3 | 260 | **CAUGHT** | multi-host camps 15->17; new bridge hosts=— |
| 19 | covenant sharpsc start dcerpc smb svcctl | Covenant | lateral_movement | 3 | 336 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 20 | SharpWMI create via DCERPC | Covenant | lateral_movement | 3 | 184 | **CAUGHT** | multi-host camps 17->19; new bridge hosts=— |
| 21 | SMB copy CreateRequest | Covenant | lateral_movement | 3 | 39 | **CAUGHT** | multi-host camps 19->20; new bridge hosts=— |
| 22 | WMI remote event subscription (ActiveScrip | Covenant | lateral_movement | 3 | 300 | **CAUGHT** | multi-host camps 20->23; new bridge hosts=— |
| 23 | WMI wbemcomn.dll hijack | Covenant | lateral_movement | 3 | 418 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 24 | DCOM ShellWindows stager | Empire | lateral_movement | 3 | 521 | **CAUGHT** | multi-host camps 23->24; new bridge hosts=— |
| 25 | MSBuild via WMI/SMB | Empire | lateral_movement | 3 | 437 | **CAUGHT** | multi-host camps 24->25; new bridge hosts=— |
| 26 | PsExec / svcctl remote service | Empire | lateral_movement | 3 | 462 | **CAUGHT** | multi-host camps 25->26; new bridge hosts=— |
| 27 | PowerShell remoting stager | Empire | lateral_movement | 3 | 245 | **CAUGHT** | multi-host camps 26->27; new bridge hosts=— |
| 28 | Remote service DLL hijack | Empire | lateral_movement | 3 | 920 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 29 | smbexec via svcctl | Empire | lateral_movement | 3 | 516 | **CAUGHT** | multi-host camps 13->14; new bridge hosts=— |
| 30 | WMI IWbemServices ExecMethod | Empire | lateral_movement | 3 | 641 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 31 | empire wmic add user backdoor | Empire | lateral_movement | 3 | 411 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 32 | schtask modification | native | lateral_movement | 2 | 46 | **CAUGHT** | multi-host camps 11->12; new bridge hosts=— |
| 33 | cmd dumping ntds dit file volume shadow co | native | credential_access | 1 | 612 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 34 | cmd seatbelt group user | native | discovery | 1 | 3 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 35 | cmd service mod fax | native | privilege_escalation | 1 | 6 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 36 | cmd sharpview pcre net | native | execution | 1 | 8 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 37 | empire launcher vbs | Empire | execution | 3 | 147 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 38 | empire mimikatz backupkeys dcerpc smb lsar | Empire | credential_access | 4 | 3544 | **CAUGHT** | multi-host camps 11->12; new bridge hosts=['acct01', 'it01', 'mkt01',  |
| 39 | empire mimikatz extract keys | Empire | credential_access | 3 | 3586 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 40 | empire mimikatz lsadump patch | Empire | credential_access | 3 | 2774 | **CAUGHT** | multi-host camps 12->13; new bridge hosts=— |
| 41 | empire ninjacopy dumping ntds dit file | Empire | credential_access | 1 | 1221 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 42 | empire persistence registry modification r | Empire | persistence | 3 | 1825 | **CAUGHT** | multi-host camps 13->14; new bridge hosts=— |
| 43 | empire powerview ldap ntsecuritydescriptor | Empire | defense_evasion | 3 | 3052 | **CAUGHT** | multi-host camps 14->15; new bridge hosts=— |
| 44 | empire psinject PEinjection | Empire | defense_evasion | 3 | 2302 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 45 | empire schtasks creation standard user | Empire | persistence | 3 | 246 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 46 | empire shell rpc samr smb group domain adm | Empire | discovery | 3 | 198 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 47 | empire shell rubeus asktgt createnetonly | Empire | credential_access | 3 | 263 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 48 | empire uac shellapi fodhelper | Empire | privilege_escalation | 3 | 324 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 49 | empire wmic add user backdoor | Empire | defense_evasion | 3 | 411 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 50 | msf record mic | Metasploit | collection | 3 | 232 | **ALREADY_COVERED** | attack hosts already inside existing multi-host campaigns |
| 51 | proxylogon ssrf rce poc | native | persistence | 1 | 296 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 52 | psh python webserver | native | execution | 1 | 8 | **SINGLE_HOST_BATCH** | batch has <2 hosts — fusion not required; campaign growth counts as so |
| 53 | PurpleSharp AD playbook I (multi-step) | PurpleSharp | playbook | 4 | 780 | **CAUGHT** | multi-host camps 15->15; new bridge hosts=['WEC', 'workstation7'] |

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

