# Stress failure modes — what broke, why, and status

Addresses CSET review feedback that “BROKE” was named without mechanism.
All cases are **synthetic** ATT&CK-shaped sketches unless noted. Authorship of
fleet-limits / breaktest manifests is **in-repo** (not an independent red team).

**Primary independence stress (external authorship):**
`reports/opensource_attack_eval.md` — OTRF/Security-Datasets + ATT&CK Evals Caldera APT3.

Author fleets (`fleet20` / `fleet-limits` / `fleet-intensive`) are **secondary**
engineering probes only. Full battery: `reports/full_capability_battery.md`.

## Taxonomy

| ID | Failure mode | Mechanism (why) | Status (2026-10-23) |
|----|--------------|-----------------|---------------------|
| lim11 | Hostname / DHCP split-brain | Events under `host-b` and `host-b-dhcp` used distinct `host_id` strings; correlator keyed on equality; enrollment also refused 1:1 producer↔two labels | **HELD** after runtime `host_aliases` + enroll-canonical-only |
| lim03 | Day-scale sleeper gaps | `_connected_host_components` + `resume_window=1h` fragmented same-user chains across multi-day quiet | **HELD** after separate `sleeper_resume_seconds` (14d) with hop/overlap gate (does **not** inflate `resume_window`) |
| lim07 | Dropped mid-chain host | Truth includes a host with no telemetry (`drop_hosts`); correlator cannot invent missing hops | **PARTIAL** (honest — incomplete evidence) |
| shared_svc | Shared svc-account over-merge | Time-windowed lateral groups unioned disjoint hop islands sharing `svc-sql` | **Unit HELD** via hop-component partition + hop-gated resume |
| noise_5k / exfil_bury | Benign egress bury | Dense CDN-like `net_conn` to one `dst_ip` buries needle; multifactor `exfil_bury` cells miss a truth host (J≈0.67) | **Unit HELD** on poison tests; **BROKE** on 3/4 intensive bury cells — bury still a live edge |
| dns_only | DNS-only C2 blind | Correlator can fuse `dns` payloads; Windows has no wevtutil DNS channel without Sysmon EID 22 | **Honest GAP** via `channel_health.dns`; correlator DNS cells mostly HELD; slow+cross DNS **PARTIAL** |
| lim09b | Sequential reuse | Same hosts, different stage shapes across ≥window gap must split | **HELD, fragile** (margin 0) — split works; confidence thin |
| fleet19 / helpdesk | Helpdesk vs APT | Concurrent legitimate lateral near APT campaign | **HELD, fragile** on all intensive helpdesk cells (margin ≤0.1) |
| break_disjoint | Disjoint credential islands | No shared user/host/egress across islands — transitive merge cannot invent a bridge | **BROKE** (expected kill shot) |
| enroll_collision | Producer slot reuse | Index-based `prod-00` reused across host namespaces → AuthError, false J=0 | **Harness fixed** — multifactor uses `prod-mf-*`, scale uses `prod-scale-*` |

## Open-source scoreboard (lead with this)

Source: `python scripts/fetch_opensource_corpora.py && python scripts/run_opensource_attack_eval.py`

| Corpus family | N | Observational verdict |
|---------------|---|------------------------|
| OTRF Empire/Covenant/PurpleSharp/schtask + Caldera APT3 day1 | **11** | all **MULTI_HOST_NO_LIFT** — multi-host campaigns form; fusion does **not** beat detector-only host coverage |

No Corvex-authored ground truth F1 on these packs (avoids self-grading). Fetch sanitizes CommandLine/ScriptBlockText so Windows Defender does not quarantine Empire dumps.

## Author-fleet scoreboard (secondary)

| Suite | N | HELD | fragile | PARTIAL | BROKE |
|-------|---|------|---------|---------|-------|
| Sealed held-out | 6 atk / 6 ben | micro-F1 **1.00** | — | — | — |
| Breaktest non-author | — | F1 ≈0.65 (lift ≈+0.44 vs detector) | — | — | — |
| Fleet20 | 20 | 20 | 1 | 0 | 0 |
| Fleet-limits T0/T1/T2 | 15 each | 14 | 5 | 1 | 0 |
| Intensive multifactor | 28 | 23 | 5 | 2 | 3 |

`claim_allowed` remains **false** (`live_second_host` gate open).

## Intensive factor pivots (where style hurts)

| Style | HELD | fragile | PARTIAL | BROKE |
|-------|------|---------|---------|-------|
| pth_lateral | 10 | 0 | 0 | 0 |
| spray | 4 | 0 | 0 | 0 |
| dns_c2 | 4 | 0 | 1 | 0 |
| helpdesk_overlap | 0 | 5 | 0 | 0 |
| exfil_bury | 0 | 0 | 1 | **3** |

Domain / container / sequence axes alone do **not** dominate failures — **exfil bury** and **helpdesk fragility** do. Cross/forest/docker host_id namespaces hold when producers are unique.

## Authorship honesty

| Corpus | Author | Independent? |
|--------|--------|--------------|
| Sealed held-out | In-repo generators, sealed before retune | No (protocol against snooping, not outsider authorship) |
| Breaktest / ART-shaped manifests | In-repo, public TTP IDs | Partial (technique IDs public; packs still author-built) |
| Fleet20 / fleet-limits / intensive | In-repo purple-team sketches | No |
| OTRF / Mordor (`labs/benign/otrf-*`) | External public dataset | **Yes origin**; `corpus_kind: mixed` cannot PASS pure-benign bars |
| Home-lab capture / S2 wevtutil | Operator machines | Deferred — required for claim softening |

## Reproduce

```bash
# Primary — external corpora
python scripts/fetch_opensource_corpora.py
python scripts/run_opensource_attack_eval.py

# Secondary — author fleets / sealed
python scripts/run_full_capability_battery.py
```
