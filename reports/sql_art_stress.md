# Continuous SQL ART stress report

Lab correlator stress only — **no live SQL injection** was executed.

- Manifest: `labs/breaktest/manifests/break_sql_continuous_art.json`
- Retries: **3** in ~**3.8219s** wall
- First host breached (scripted): **host-a** at **T+42.0s** (FIRST_COMPROMISE method=stacked_xp_cmdshell_success)
- Truth compromised hosts: host-a, host-b, host-c
- Saved hosts (innocent + not falsely quarantined): **2** -> host-d, host-e
- Falsely quarantined (dry-run): **0** -> —
- Correlator match rate across retries: **1.0** (mean Jaccard **1.0**)
- Where it stayed / broke: over-merge residual **[]**; missed **[]**

## Per-host detail (last successful attempt)

| Host | Role | Compromised | Flagged | Over-merge | Quarantine dry-run | Saved | Methods |
|------|------|-------------|---------|------------|--------------------|-------|---------|
| host-a | web-front / SQLi entry (truth compromised) | yes | yes | no | yes | no | union_select_probe, boolean_blind_retry, time_based_blind_retry, credential_spray_sql_logins, ... |
| host-b | SQL primary (truth compromised) | yes | yes | no | yes | no | stolen_sa_lateral, retry_sa_hop, svc_account_reuse_burst, bulk_table_dump, ... |
| host-c | SQL replica + app (truth compromised) | yes | yes | no | yes | no | linked_server_hop, retry_linked_server, svc_account_reuse_burst, bulk_table_dump_retry, ... |
| host-d | DBA workstation (innocent — save target) | no | no | no | no | yes | benign DBA — shared sql-svc over-merge bait, benign DBA SSMS browse |
| host-e | BI reporting client (innocent — save target) | no | no | no | no | yes | benign BI job — shared sql-svc over-merge bait, benign CDN / PowerBI refresh |

## Retry attempts

| # | OK | Wall s | Jaccard | Matched | Over-merged | Quarantine proposed |
|---|----|--------|---------|---------|-------------|---------------------|
| 1 | yes | 1.0597 | 1.0 | True | - | host-a, host-b, host-c |
| 2 | yes | 1.089 | 1.0 | True | - | host-a, host-b, host-c |
| 3 | yes | 1.585 | 1.0 | True | - | host-a, host-b, host-c |

## Honesty

- Quarantine column is **dry-run IsolateHost proposals**, not live OS quarantine.
- DNS OOB SQLi channels are intentional blind spots in current detectors.
- Saved = innocent host not falsely proposed for isolate.
