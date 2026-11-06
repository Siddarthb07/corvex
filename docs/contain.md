# Contain

Default is observe-only. `CORVEX_CONTAIN=0` logs isolate proposals and does not mutate a host. `claim_allowed` stays false. This is not enterprise EDR.

## Modes

| Mode | When | What it does |
|------|------|----------------|
| `dry_run` | `CORVEX_CONTAIN=0` (default) | Log `IsolateHost`. No firewall change. |
| `lab_flag` | `LAB_DIR` / `CORVEX_LAB_DIR` / `--lab-dir` | Write sandbox flag files virtual lab hosts honor. Not OS quarantine. |
| `blocked` | `CORVEX_CONTAIN!=0` and Security L1 incomplete | Refuse. Dry-run proposals only. |
| `live_windows` | `CORVEX_CONTAIN!=0` and L1 complete | Capability signal for local Windows Firewall self-isolate. Execute still needs hostile-bus + `CORVEX_CONTAIN_AUTHZ`. |

`quarantine-status` reports `live_executor_kind=windows_firewall_self_isolate` only in `live_windows`. Otherwise the kind is null (`lab_flag` when the lab dir is set).

## Windows Firewall self-isolate

`corvex.contain.windows_firewall` creates a named rule `Corvex-Isolate-<host_id>` on the **local** host (`CORVEX_LOCAL_HOST_ID`, else the short hostname). `enforced=true` only after the rule is created and verified. Non-Windows refuses. A remote host is not isolated by this executor.

Unlock for a real rule:

1. Every Security L1 key is evidenced true
2. `corvex hostile-bus-test` pass (`reports/hostile_bus_selftest.json`)
3. `CORVEX_CONTAIN!=0`
4. `CORVEX_CONTAIN_AUTHZ` set to a unique secret (no hardcoded fallback; `lab-dual-control-token`, `changeme`, `shared`, `default` are rejected)
5. Target host_id matches this machine, or `--lab-dir` for sandbox flags

```bash
corvex contain-dry-run IsolateHost --host host-a --rationale "demo"
corvex quarantine host-a --rationale "mid-chain"          # dry-run
corvex quarantine host-a --rationale "local" --enforce --authz "$CORVEX_CONTAIN_AUTHZ"
corvex quarantine-status
```

Windows Firewall self-isolate is not VLAN segmentation and not an EDR quarantine.

## Severity policy and EstateLockdown

Policy file: `~/.corvex/contain_policy.json` or `CORVEX_CONTAIN_POLICY`. Defaults: `auto_enforce=false`, SOC allowlist never isolated, dual-control for multi-host and for estate scope.

`corvex.contain.severity.resolve_isolate_scope` maps a campaign to a band:

| Band | Scope | Verb |
|------|--------|------|
| `observe` | none | no targets |
| `low` | flagged hosts | `IsolateHost` |
| `medium` | peer-risk neighborhood (stage hosts ∩ estate) | `IsolateHost` |
| `critical` | estate minus SOC allowlist | `EstateLockdown` |

Critical can also trip on absolute pace (default: ≥5 hosts inside 30 minutes with exfil, DNS, or lateral+stage diversity), not only on fraction of estate N. Blast-radius caps refuse a plan that exceeds the band's max % of N. The dashboard `contain_plan` is this scope, read-only. It does not call the OS.

```bash
corvex contain-policy-show
corvex contain-policy-init --soc-allowlist soc-jump
corvex contain-severity --hosts host-a,host-b --estate host-a,host-b,host-c
```

`EstateLockdown` at the edge is still one `IsolateHost` per target. Fanout strips the SOC allowlist before it sends anything.

## Agent inbox

`corvex agent-contain` heartbeats and drains `runs/contain-agent/inbox.jsonl` (override with `CORVEX_AGENT_DIR`). Apply goes through the same live gates. v1 trusts the local inbox; HMAC enrollment wrap is not the transport yet. An envelope in the inbox does not bypass `CORVEX_CONTAIN=0`.

```bash
corvex agent-contain --once
corvex agent-contain --follow --poll-seconds 2
```

## SSH fanout

Peers: `~/.corvex/contain_peers.json` or `CORVEX_CONTAIN_PEERS`.

```json
{ "host-pc-2": { "ssh": "user@192.0.2.20", "identity": "~/.ssh/corvex_s2" } }
```

```bash
corvex quarantine-fanout host-a,host-pc-2 --rationale "peer cut"            # dry-run default
corvex quarantine-fanout host-a --rationale "peer cut" --enforce --authz "$CORVEX_CONTAIN_AUTHZ"
```

Missing peer → `no_peer`, not a silent success. Remote apply is `corvex quarantine-apply` over SSH. Dry-run does not change a remote firewall.

## Deferred

- **S5** pure-benign baseline (primary + secondary) is not passed. Do not soften the public claim.
- The paper is deferred. Sealed synthetic F1 is not enterprise validation.
- DNS channel GAP remains a blind spot for DNS-only C2.
- No process-kill executor. Unknown verbs refuse.
