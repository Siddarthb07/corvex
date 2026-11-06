# Full Corvex capability battery

Generated: **2026-11-06T09:29:48Z**

Standing claim unchanged: synthetic ATT&CK-shaped fleets only; **claim_allowed=True**.

Wall: **153.6376s** | Steps ok: **11/13**

## Scoreboard rollup

| Suite | N | HELD | fragile | PARTIAL | BROKE | Notes |
|-------|---|------|---------|---------|-------|-------|
| fleet-limits | 15 | 14 | 5 | 1 | 0 |  |
| fleet20 | 20 | 20 | 2 | 0 | 0 |  |
| intensive | 28 | 27 | 6 | 1 | 0 | domain×container×sequence×style matrix |
| fleet-limits-t1 | 15 | 14 | 5 | 1 | 0 |  |
| fleet-limits-t2 | 15 | 14 | 5 | 1 | 0 |  |
| sealed-heldout | None | — | — | — | — | see metrics.heldout; micro-F1 in RESULTS.md |
| breaktest-non-author | — | — | — | — | — | lift=None |

## Exact break list (BROKE + PARTIAL across suites)

| Suite | Campaign | Verdict | J | Why |
|-------|----------|---------|---|-----|
| fleet-limits | `lim07-dropped-mid-chain` | **PARTIAL** | 0.5 | jaccard 0.5 in PARTIAL band |
| intensive | `mf-cross-bare-slow-dns_c2` | **PARTIAL** | 0.6667 | jaccard 0.6667 in PARTIAL band |
| fleet-limits-t1 | `t1-lim07-dropped-mid-chain` | **PARTIAL** | 0.5 | jaccard 0.5 in PARTIAL band |
| fleet-limits-t2 | `t2-lim07-dropped-mid-chain` | **PARTIAL** | 0.5 | jaccard 0.5 in PARTIAL band |
| breakers | `break-disjoint-islands` | **BROKE** | 0.4 | Two credential islands with no shared user, shared egress, or shared host — correlator cannot transitively fuse. Expect missed_hosts / both_missed vs full 5-host truth. |

## Sealed / breaktest metrics

```json
{
  "heldout": {
    "split": "heldout",
    "pass": true,
    "metrics": {
      "correlator": {
        "campaign_f1": 1.0,
        "macro_campaign_f1": 1.0,
        "precision": 1.0,
        "recall": 1.0,
        "precision_at_1": 1.0,
        "false_campaign_rate": 0.0,
        "ttu_seconds": 0.004691300000000009,
        "tp": 6.0,
        "fp": 0.0,
        "fn": 0.0,
        "f1_aggregation": "micro_from_tp_fp_fn"
      },
      "b1": {
        "campaign_f1": 0.0,
        "macro_campaign_f1": 0.0,
        "precision": 0.0,
        "recall": 0.0,
        "precision_at_1": 0.0,
        "false_campaign_rate": 1.0,
        "ttu_seconds": 1.6000000000016e-05,
        "tp": 0.0,
        "fp": 1.0,
        "fn": 6.0,
        "f1_aggregation": "micro_from_tp_fp_fn"
      },
      "b2": {
        "campaign_f1": 0.6666666666666667,
        "macro_campaign_f1": 0.8333333333333334,
        "precision": 0.5555555555555556,
        "recall": 0.8333333333333334,
        "precision_at_1": 0.8333333333333334,
        "false_campaign_rate": 0.0,
        "ttu_seconds": 3.049999999998887e-05,
        "tp": 5.0,
        "fp": 4.0,
        "fn": 1.0,
        "f1_aggregation": "micro_from_tp_fp_fn"
      },
      "detector_only": {
        "campaign_f1": 0.625,
        "macro_campaign_f1": 0.7777777777777778,
        "precision": 0.5,
        "recall": 0.8333333333333334,
        "precision_at_1": 0.8333333333333334,
        "false_campaign_rate": 0.0,
        "ttu_seconds": 0.00770930000000003,
        "tp": 5.0,
        "fp": 5.0,
        "fn": 1.0,
        "f1_aggregation": "micro_from_tp_fp_fn"
      }
    },
    "care_vs_incumbent": "unproven",
    "care_banner": "care vs incumbent unproven",
    "ood_note": "OOD packs are author-designed; no generalization claim beyond lab grammar.",
    "b2_train_floor_ok": true
  },
  "non_author": {
    "source": "labs/breaktest/manifests",
    "correlator": {
      "campaign_f1": 0.8,
      "macro_campaign_f1": 0.8484848484848485,
      "precision": 0.7142857142857143,
      "recall": 0.9090909090909091,
      "precision_at_1": 0.9090909090909091,
      "false_campaign_rate": 0.0,
      "ttu_seconds": 0.0075303000000000175,
      "tp": 10.0,
      "fp": 4.0,
      "fn": 1.0,
      "f1_aggregation": "micro_from_tp_fp_fn"
    },
    "detector_only": {
      "campaign_f1": 0.20833333333333334,
      "macro_campaign_f1": 0.21515151515151515,
      "precision": 0.13513513513513514,
      "recall": 0.45454545454545453,
      "precision_at_1": 0.18181818181818182,
      "false_campaign_rate": 0.0,
      "ttu_seconds": 0.007628400000000007,
      "tp": 5.0,
      "fp": 32.0,
      "fn": 6.0,
      "f1_aggregation": "micro_from_tp_fp_fn"
    },
    "f1_lift": 0.5916666666666667,
    "pass": true,
    "note": "Public-TTP/breaktest manifest score. Still not stranger Windows telemetry \u2014 necessary but not sufficient for claim_allowed.",
    "honesty": "Breaktest manifests are public-TTP shaped, not independent enterprise traffic."
  },
  "claim_gates": {
    "schema_ver": "3",
    "generated_at": "2026-11-06T09:27:23Z",
    "claim_allowed": true,
    "lab_verified": true,
    "claim_language": "useful on real attacks",
    "gates": {
      "non_author_fusion_lift": {
        "id": "non_author_fusion_lift",
        "pass": true,
        "f1_lift": 0.5916666666666667,
        "min_lift": 0.05,
        "source": "labs/breaktest/manifests",
        "note": "Public-TTP/breaktest manifest score. Still not stranger Windows telemetry \u2014 necessary but not sufficient for claim_allowed."
      },
      "stranger_success": {
        "id": "stranger_success",
        "pass": true,
        "path": "reports/stranger_dry_run.json",
        "operator": "Jack",
        "attestation_kind": "human",
        "attestation_custody": "stranger_private_key",
        "attestation_signed": true,
        "note": "Completed Windows export \u2192 byo-windows \u2192 timeline without author help."
      },
      "benign_fcr_real_n": {
        "id": "benign_fcr_real_n",
        "pass": true,
        "n_benign": 6,
        "min_n": 5,
        "false_campaign_rate": 0.0,
        "max_fcr": 0.1,
        "note": "Held-out benign N=6 (need >=5), FCR=0.000."
      },
      "trust_integrity": {
        "id": "trust_integrity",
        "pass": true,
        "checks": {
          "correlator_ingest_rejects_bad_hmac": true,
          "correlator_rejects_without_enrollment": true,
          "resign_keeps_verified": true,
          "resign_tags_local_stamp": true,
          "dash_boot_no_embed": true
        },
        "note": "Functional probes green."
      },
      "live_second_host": {
        "id": "live_second_host",
        "pass": true,
        "path": "reports/live_second_host.json",
        "note": "Elevated wevtutil Security channel evidence."
      }
    },
    "honesty": "Do not publish 'useful on real attacks' until claim_allowed=true. Author-held HMAC and unsigned stranger JSON are advisory. lab_verified means sealed/breaktest + trust probes only."
  },
  "sql_art": {
    "test": "Continuous SQL ART stress",
    "manifest": "labs/breaktest/manifests/break_sql_continuous_art.json",
    "retries": 8,
    "total_wall_seconds": 6.8267,
    "summary": {
      "truth_hosts": [
        "host-a",
        "host-b",
        "host-c"
      ],
      "hosts_saved": [
        "host-d",
        "host-e"
      ],
      "hosts_saved_count": 2,
      "false_quarantine": [],
      "false_quarantine_count": 0,
      "match_rate": 1.0,
      "mean_jaccard": 1.0,
      "common_over_merged": [],
      "common_missed": [],
      "held": "truth APT {a,b,c} matched",
      "broke_on": [
        "none_stable"
      ]
    },
    "honesty": "Synthetic ART-style event sketches. No live SQLi. Quarantine = dry-run proposals only. CORVEX_CONTAIN remains locked."
  }
}
```

## Step log

| Step | OK | Wall (s) |
|------|----|----------|
| `pytest` | NO | 6.7876 |
| `eval-heldout` | yes | 0.5568 |
| `score-non-author` | yes | 0.4624 |
| `claim-gates` | yes | 0.3784 |
| `fleet20` | NO | 16.5885 |
| `fleet-limits` | yes | 25.3377 |
| `breakers` | yes | 1.3209 |
| `sql-art` | yes | 7.0915 |
| `intensive` | yes | 41.1873 |
| `opensource-fetch` | yes | 1.205 |
| `opensource-eval` | yes | 26.7564 |
| `fleet-limits-t1` | yes | 13.3709 |
| `fleet-limits-t2` | yes | 12.5248 |

## Honesty

- All suites are lab/synthetic unless noted.
- Intensive domain/container axes are host_id namespaces, not live AD/K8s.
- See `reports/intensive_capability_matrix.md` and `docs/stress-failure-modes.md`.

