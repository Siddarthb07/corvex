# Full Corvex capability battery

Generated: **2026-10-23T15:31:40Z**

Standing claim unchanged: synthetic ATT&CK-shaped fleets only; **claim_allowed=False**.

Wall: **Nones** | Steps ok: **11/11**

## Scoreboard rollup

| Suite | N | HELD | fragile | PARTIAL | BROKE | Notes |
|-------|---|------|---------|---------|-------|-------|
| fleet-limits | 15 | 14 | 5 | 1 | 0 |  |
| fleet20 | 20 | 20 | 1 | 0 | 0 |  |
| intensive | 28 | 23 | 5 | 2 | 3 | domain×container×sequence×style matrix |
| fleet-limits-t1 | 15 | 14 | 5 | 1 | 0 | 15 hosts; producers prod-scale-* |
| fleet-limits-t2 | 15 | 14 | 5 | 1 | 0 | 50 hosts; producers prod-scale-* |
| sealed-heldout | — | — | — | — | — | micro-F1 correlator 1.00 / detector 0.625 (N_atk=6, N_ben=6) |
| breaktest-non-author | — | — | — | — | — | lift=0.4410796576695194 |

## Exact break list (BROKE + PARTIAL across suites)

| Suite | Campaign | Verdict | J | Why |
|-------|----------|---------|---|-----|
| fleet-limits | `lim07-dropped-mid-chain` | **PARTIAL** | 0.5 | jaccard 0.5 in PARTIAL band |
| intensive | `mf-single-bare-burst-exfil_bury` | **BROKE** | 0.6667 | truth never recovered: ['corp-ws03'] |
| intensive | `mf-forest-mixed-concurrent-exfil_bury` | **PARTIAL** | 0.8333 | multi-campaign mean/min jaccard=0.8333/0.6667 |
| intensive | `mf-cross-bare-slow-dns_c2` | **PARTIAL** | 0.6667 | jaccard 0.6667 in PARTIAL band |
| intensive | `mf-single-docker-ooo-exfil_bury` | **BROKE** | 0.6667 | truth never recovered: ['ctr-ws03-db'] |
| intensive | `mf-single-bare-slow-exfil_bury` | **BROKE** | 0.6667 | truth never recovered: ['corp-ws03'] |
| fleet-limits-t1 | `t1-lim07-dropped-mid-chain` | **PARTIAL** | 0.5 | jaccard 0.5 in PARTIAL band |
| fleet-limits-t2 | `t2-lim07-dropped-mid-chain` | **PARTIAL** | 0.5 | jaccard 0.5 in PARTIAL band |
| breakers | `break-disjoint-islands` | **BROKE** | 0.4 | Two credential islands with no shared user, shared egress, or shared host — correlator cannot transitively fuse. Expect missed_hosts / both_missed vs full 5-host truth. |

## Sealed / breaktest metrics

```json
{
  "heldout": {
    "split": "heldout",
    "pass": true,
    "gate": {
      "pass": true,
      "reasons": []
    },
    "reasons": [],
    "metrics": {
      "correlator": {
        "campaign_f1": 1.0,
        "macro_campaign_f1": 1.0,
        "precision": 1.0,
        "recall": 1.0,
        "precision_at_1": 1.0,
        "false_campaign_rate": 0.0,
        "ttu_seconds": 0.006975100000000012,
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
        "ttu_seconds": 4.4200000000049755e-05,
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
        "ttu_seconds": 4.2199999999992244e-05,
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
        "ttu_seconds": 0.00847549999999997,
        "tp": 5.0,
        "fp": 5.0,
        "fn": 1.0,
        "f1_aggregation": "micro_from_tp_fp_fn"
      }
    },
    "by_family": {
      "correlator": {
        "benign": {
          "campaign_f1": 1.0,
          "macro_campaign_f1": 1.0,
          "precision": 1.0,
          "recall": 1.0,
          "precision_at_1": 1.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 0.0067609999999999615,
          "tp": 0.0,
          "fp": 0.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "exfil": {
          "campaign_f1": 1.0,
          "macro_campaign_f1": 1.0,
          "precision": 1.0,
          "recall": 1.0,
          "precision_at_1": 1.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 0.006975100000000012,
          "tp": 2.0,
          "fp": 0.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "fusion_chain": {
          "campaign_f1": 1.0,
          "macro_campaign_f1": 1.0,
          "precision": 1.0,
          "recall": 1.0,
          "precision_at_1": 1.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 0.0046872000000000025,
          "tp": 1.0,
          "fp": 0.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "lateral": {
          "campaign_f1": 1.0,
          "macro_campaign_f1": 1.0,
          "precision": 1.0,
          "recall": 1.0,
          "precision_at_1": 1.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 0.0038526999999999867,
          "tp": 2.0,
          "fp": 0.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "recon_lateral": {
          "campaign_f1": 1.0,
          "macro_campaign_f1": 1.0,
          "precision": 1.0,
          "recall": 1.0,
          "precision_at_1": 1.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 0.004030499999999992,
          "tp": 1.0,
          "fp": 0.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        }
      },
      "b1": {
        "benign": {
          "campaign_f1": 0.0,
          "macro_campaign_f1": 0.0,
          "precision": 0.0,
          "recall": 0.0,
          "precision_at_1": 0.0,
          "false_campaign_rate": 1.0,
          "ttu_seconds": 4.4200000000049755e-05,
          "tp": 0.0,
          "fp": 0.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "exfil": {
          "campaign_f1": 0.0,
          "macro_campaign_f1": 0.0,
          "precision": 0.0,
          "recall": 0.0,
          "precision_at_1": 0.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 1.0999999999983245e-05,
          "tp": 0.0,
          "fp": 0.0,
          "fn": 2.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "fusion_chain": {
          "campaign_f1": 0.0,
          "macro_campaign_f1": 0.0,
          "precision": 0.0,
          "recall": 0.0,
          "precision_at_1": 0.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 1.1700000000003374e-05,
          "tp": 0.0,
          "fp": 0.0,
          "fn": 1.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "lateral": {
          "campaign_f1": 0.0,
          "macro_campaign_f1": 0.0,
          "precision": 0.0,
          "recall": 0.0,
          "precision_at_1": 0.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 8.499999999966867e-06,
          "tp": 0.0,
          "fp": 0.0,
          "fn": 2.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "recon_lateral": {
          "campaign_f1": 0.0,
          "macro_campaign_f1": 0.0,
          "precision": 0.0,
          "recall": 0.0,
          "precision_at_1": 0.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 1.4199999999964241e-05,
          "tp": 0.0,
          "fp": 1.0,
          "fn": 1.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        }
      },
      "b2": {
        "benign": {
          "campaign_f1": 1.0,
          "macro_campaign_f1": 1.0,
          "precision": 1.0,
          "recall": 1.0,
          "precision_at_1": 1.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 4.2199999999992244e-05,
          "tp": 0.0,
          "fp": 0.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "exfil": {
          "campaign_f1": 1.0,
          "macro_campaign_f1": 1.0,
          "precision": 1.0,
          "recall": 1.0,
          "precision_at_1": 1.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 1.3200000000046508e-05,
          "tp": 2.0,
          "fp": 0.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "fusion_chain": {
          "campaign_f1": 0.0,
          "macro_campaign_f1": 0.0,
          "precision": 0.0,
          "recall": 0.0,
          "precision_at_1": 0.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 1.8799999999985495e-05,
          "tp": 0.0,
          "fp": 4.0,
          "fn": 1.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "lateral": {
          "campaign_f1": 1.0,
          "macro_campaign_f1": 1.0,
          "precision": 1.0,
          "recall": 1.0,
          "precision_at_1": 1.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 9.700000000001374e-06,
          "tp": 2.0,
          "fp": 0.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "recon_lateral": {
          "campaign_f1": 1.0,
          "macro_campaign_f1": 1.0,
          "precision": 1.0,
          "recall": 1.0,
          "precision_at_1": 1.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 1.689999999998637e-05,
          "tp": 1.0,
          "fp": 0.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        }
      },
      "detector_only": {
        "benign": {
          "campaign_f1": 1.0,
          "macro_campaign_f1": 1.0,
          "precision": 1.0,
          "recall": 1.0,
          "precision_at_1": 1.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 0.007291500000000006,
          "tp": 0.0,
          "fp": 0.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "exfil": {
          "campaign_f1": 1.0,
          "macro_campaign_f1": 1.0,
          "precision": 1.0,
          "recall": 1.0,
          "precision_at_1": 1.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 0.007355800000000023,
          "tp": 2.0,
          "fp": 0.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "fusion_chain": {
          "campaign_f1": 0.0,
          "macro_campaign_f1": 0.0,
          "precision": 0.0,
          "recall": 0.0,
          "precision_at_1": 0.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 0.00847549999999997,
          "tp": 0.0,
          "fp": 4.0,
          "fn": 1.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "lateral": {
          "campaign_f1": 1.0,
          "macro_campaign_f1": 1.0,
          "precision": 1.0,
          "recall": 1.0,
          "precision_at_1": 1.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 0.0034594000000000014,
          "tp": 2.0,
          "fp": 0.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        },
        "recon_lateral": {
          "campaign_f1": 0.6666666666666666,
          "macro_campaign_f1": 0.6666666666666666,
          "precision": 0.5,
          "recall": 1.0,
          "precision_at_1": 1.0,
          "false_campaign_rate": 0.0,
          "ttu_seconds": 0.004622300000000024,
          "tp": 1.0,
          "fp": 1.0,
          "fn": 0.0,
          "f1_aggregation": "micro_from_tp_fp_fn"
        }
      }
    },
    "vs_b1": {
      "correlator_f1": 1.0,
      "baseline_f1": 0.0,
      "f1_lift": 1.0,
      "correlator_recall": 1.0,
      "baseline_recall": 0.0,
      "recall_lift": 1.0,
      "correlator_precision": 1.0,
      "baseline_precision": 0.0,
      "baseline_false_campaign_rate": 1.0,
      "correlator_false_campaign_rate": 0.0
    },
    "contain_dry_run": {
      "hosts_proposed": 21,
      "hosts_correct": 21,
      "false_isolates": 0,
      "missed_hosts": 0,
      "false_isolate_rate": 0.0,
      "isolate_precision": 1.0,
      "isolate_recall": 1.0
    },
    "packs": [
      {
        "pack": "held-benign-a.jsonl",
        "family": "benign",
        "ood": false
      },
      {
        "pack": "held-benign-b.jsonl",
        "family": "benign",
        "ood": false
      },
      {
        "pack": "held-benign-c.jsonl",
        "family": "benign",
        "ood": false
      },
      {
        "pack": "held-benign-d.jsonl",
        "family": "benign",
        "ood": false
      },
      {
        "pack": "held-benign-e.jsonl",
        "family": "benign",
        "ood": false
      },
      {
        "pack": "held-benign-f.jsonl",
        "family": "benign",
        "ood": false
      },
      {
        "pack": "held-exfil-b.jsonl",
        "family": "exfil",
        "ood": true
      },
      {
        "pack": "held-exfil.jsonl",
        "family": "exfil",
        "ood": false
      },
      {
        "pack": "held-fusion-chain.jsonl",
        "family": "fusion_chain",
        "ood": true
      },
      {
        "pack": "held-lateral-b.jsonl",
        "family": "lateral",
        "ood": false
      },
      {
        "pack": "held-lateral-ood.jsonl",
        "family": "lateral",
        "ood": true
      },
      {
        "pack": "held-recon-lateral.jsonl",
        "family": "recon_lateral",
        "ood": true
      }
    ],
    "ablation": {
      "raw_f1": 1.0,
      "detector_only_f1": 0.625,
      "b1_f1": 0.0,
      "b2_f1": 0.6666666666666667,
      "correlator_precision": 1.0,
      "correlator_recall": 1.0,
      "b1_precision": 0.0,
      "b1_recall": 0.0
    },
    "freeze_manifest": {
      "correlator_sha": "bbce0e7577df181d2fddf41d78072d28040aa32ab8072e3f94b59d8ee5891536",
      "detectors_sha": "27c6de357ccd7ead931822b0038f997595867863d8eaeb071c240565146426e1",
      "scorer_sha": "65e692da0f2160e78b79069d51880532fb5aa79fdfd1d4c680eaed81e1a2d1c8",
      "b2_sha": "189b6c6099547204a97997ec7bd0be167e607ea84878c5f1ba97408342579ba7",
      "config_sha": "fed0c4ed9eb59049755eda0908b1b0056c19a576ee5bb5e6fbbbc26c446493c9"
    },
    "care_vs_incumbent": "unproven",
    "care_banner": "care vs incumbent unproven",
    "ood_note": "OOD packs are author-designed; no generalization claim beyond lab grammar.",
    "b2_train_floor_ok": true
  },
  "non_author": {
    "source": "labs/breaktest/manifests",
    "packs": [
      "art_cred_hop.json",
      "art_lateral_chain.atomic.json",
      "art_lateral_chain.json",
      "art_recon_exfil_split.json",
      "art_recon_pivot.json",
      "art_slow_drip.json",
      "break_blind_dns_c2.json",
      "break_cdn_bridge_compound.json",
      "break_disjoint_islands.json",
      "break_overmerge_jumpbox.json",
      "break_sql_continuous_art.json"
    ],
    "skipped": [
      {
        "file": "break_os_wide_sensors.json",
        "reason": "manifest missing ['steps']"
      }
    ],
    "correlator": {
      "campaign_f1": 0.6451612903225806,
      "macro_campaign_f1": 0.6666666666666667,
      "precision": 0.5,
      "recall": 0.9090909090909091,
      "precision_at_1": 0.9090909090909091,
      "false_campaign_rate": 0.0,
      "ttu_seconds": 0.006591400000000025,
      "tp": 10.0,
      "fp": 10.0,
      "fn": 1.0,
      "f1_aggregation": "micro_from_tp_fp_fn"
    },
    "detector_only": {
      "campaign_f1": 0.2040816326530612,
      "macro_campaign_f1": 0.2,
      "precision": 0.13157894736842105,
      "recall": 0.45454545454545453,
      "precision_at_1": 0.18181818181818182,
      "false_campaign_rate": 0.0,
      "ttu_seconds": 0.008854699999999993,
      "tp": 5.0,
      "fp": 33.0,
      "fn": 6.0,
      "f1_aggregation": "micro_from_tp_fp_fn"
    },
    "f1_lift": 0.4410796576695194,
    "pass": true,
    "note": "Public-TTP/breaktest manifest score. Still not stranger Windows telemetry \u2014 necessary but not sufficient for claim_allowed.",
    "honesty": "Breaktest manifests are public-TTP shaped, not independent enterprise traffic."
  },
  "claim_gates": {
    "schema_ver": "3",
    "generated_at": "2026-10-23T15:27:32Z",
    "claim_allowed": false,
    "lab_verified": true,
    "claim_language": "lab_verified \u2014 sealed held-out + breaktest + trust probes; need Ed25519 stranger self-sign + live second host for claim_allowed",
    "gates": {
      "non_author_fusion_lift": {
        "id": "non_author_fusion_lift",
        "pass": true,
        "f1_lift": 0.4410796576695194,
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
        "pass": false,
        "path": "reports/live_second_host.json",
        "note": "FAIL: missing reports/live_second_host.json \u2014 elevated wevtutil on a second physical Windows host (see docs/trust-hardening.md)."
      }
    },
    "honesty": "Do not publish 'useful on real attacks' until claim_allowed=true. Author-held HMAC and unsigned stranger JSON are advisory. lab_verified means sealed/breaktest + trust probes only."
  }
}
```

## Step log

| Step | OK | Wall (s) |
|------|----|----------|
| `pytest` | yes | None |
| `eval-heldout` | yes | None |
| `score-non-author` | yes | None |
| `claim-gates` | yes | None |
| `fleet20` | yes | None |
| `fleet-limits` | yes | None |
| `breakers` | yes | None |
| `sql-art` | yes | None |
| `intensive` | yes | None |
| `fleet-limits-t1` | yes | None |
| `fleet-limits-t2` | yes | None |

## Honesty

- All suites are lab/synthetic unless noted.
- Intensive domain/container axes are host_id namespaces, not live AD/K8s.
- See `reports/intensive_capability_matrix.md` and `docs/stress-failure-modes.md`.

