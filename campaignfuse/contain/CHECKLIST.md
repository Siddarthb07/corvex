# Security L1 checklist (Stage D gate)

All items must be **true** in `reports/security_l1_checklist.json` before Contain unlocks.

| Key | Requirement |
|-----|-------------|
| `mtls_identities` | mTLS identities for every actuator/control plane peer |
| `typed_commands` | Typed commands only (no free-form shell) |
| `authz_neq_sig` | Authorization ≠ signature (separate authz decision) |
| `anti_replay` | Anti-replay (nonce/window) on commands |
| `dual_control` | Dual-control for destructive verbs |
| `fail_closed` | Fail-closed on auth/policy errors |
| `least_privilege` | Least privilege execution role |
| `immutable_audit` | Immutable / hash-chained audit |
| `oversight_off_data_plane` | Oversight plane off data plane |
| `no_free_form_shell` | No free-form shell executor |
| `blast_radius_caps` | Blast-radius caps enforced |

Draft destructive Action verbs (not installed): `drafts/actions/`.
